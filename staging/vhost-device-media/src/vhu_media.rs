use std::{
    convert,
    io::{self, Result as IoResult, Write},
    path::Path,
};

use async_mutex::Mutex;
use log::{debug, error, warn};
use ref_cast::RefCast;
use vhost::vhost_user::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock, VringT};
use virtio_bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
    Le32,
};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{vhu_media_thread::VhostUserMediaThread, ThisError};

pub(crate) const VIRTIO_V4L2_CARD_NAME_LEN: usize = 32;

pub(crate) type Result<T> = std::result::Result<T, VuMediaError>;
pub(crate) type DescriptorChainMemory = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

#[derive(RefCast)]
#[repr(transparent)]
struct MediaDescriptorChain(DescriptorChainMemory);

impl std::io::Read for MediaDescriptorChain {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let descriptor = self.0.clone().collect::<Vec<_>>()[0];
        self.0
            .memory()
            .read_slice(buf, descriptor.addr())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(0)
    }
}

impl std::io::Write for MediaDescriptorChain {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let descriptor = self.0.clone().collect::<Vec<_>>()[0];
        self.0
            .memory()
            .write_slice(buf, descriptor.addr())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(0)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

const QUEUE_SIZE: usize = 256;
const NUM_QUEUES: usize = 2;
const COMMAND_Q: u16 = 0;
pub const EVENT_Q: u16 = 1;

#[derive(Debug, ThisError)]
/// Errors related to vhost-device-media daemon.
pub(crate) enum VuMediaError {
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Can't create eventFd")]
    EventFdError,
    #[error("Failed to handle event")]
    HandleEventNotEpollIn,
    #[error("Unknown device event")]
    HandleUnknownEvent,
    #[error("Too many descriptors: {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected at least: {0}, found: {1}")]
    UnexpectedMinimumDescriptorSize(usize, usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("No memory configured")]
    NoMemoryConfigured,
}

impl convert::From<VuMediaError> for io::Error {
    fn from(e: VuMediaError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

/// Virtio Media Configuration
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioMediaConfig {
    /// The device_caps field of struct video_device.
    device_caps: Le32,
    /// The vfl_devnode_type of the device.
    device_type: Le32,
    /// The `card` field of v4l2_capability.
    card: [u8; VIRTIO_V4L2_CARD_NAME_LEN],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioMediaConfig {}

pub(crate) struct VuMediaBackend {
    config: VirtioMediaConfig,
    pub threads: Vec<Mutex<VhostUserMediaThread>>,
    pub exit_event: EventFd,
}

impl VuMediaBackend {
    /// Create a new virtio video device for /dev/video<num>.
    pub fn new(video_path: &Path) -> Result<Self> {
        use v4l2r::ioctl::Capabilities;
        let backend = VhostUserMediaThread::new(video_path)?;
        Ok(Self {
            config: VirtioMediaConfig {
                device_caps: (Capabilities::VIDEO_CAPTURE_MPLANE | Capabilities::STREAMING)
                    .bits()
                    .into(),
                device_type: 0.into(),
                card: [0; VIRTIO_V4L2_CARD_NAME_LEN],
            },
            threads: vec![Mutex::new(VhostUserMediaThread::new(backend.clone())?)],
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuMediaError::EventFdError)?,
        })
    }
}

/// VhostUserBackend trait methods
impl VhostUserBackend for VuMediaBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        debug!("Num queues called");
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        debug!("Max queue size called");
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        debug!("Features called");
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        debug!("Protocol features called");
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&self, enabled: bool) {
        for thread in self.threads.iter() {
            thread.lock().unwrap().event_idx = enabled;
        }
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        for thread in self.threads.iter() {
            thread.lock().unwrap().mem = Some(mem.clone());
        }
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        debug!("Handle event called");
        if evset != EventSet::IN {
            warn!("Non-input event");
            return Err(VuMediaError::HandleEventNotEpollIn.into());
        }
        let mut thread = self.threads[thread_id].lock().unwrap();
        if self.vrings.is_empty() {
            self.vrings = Vec::from(vrings);
        }

        match device_event {
            COMMAND_Q => {
                let vring = &vrings[COMMAND_Q as usize];
                //

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        debug!("calling it here");
                        vring.disable_notification().unwrap();
                        thread.process_command_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_command_queue(vring)?;
                }
            }

            EVENT_Q => {
                let vring = &vrings[EVENT_Q as usize];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_event_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_event_queue(vring)?;
                }
            }

            _ => {
                warn!("unhandled device_event: {}", device_event);
                return Err(VuMediaError::HandleUnknownEvent.into());
            }
        }
        debug!("Handle event finished");
        Ok(())
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        warn!("Getting config");
        let offset = _offset as usize;
        let size = _size as usize;

        let buf = self.config.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        debug!("Exit event called");
        self.exit_event.try_clone().ok()
    }
}

/*impl VirtioMediaGuestMemoryMapper for VuMediaBackend {
    type GuestMemoryMapping = GuestMemoryAtomic<GuestMemoryMmap>;

    fn new_mapping(&self, sgs: Vec<SgEntry>) -> anyResult<Self::GuestMemoryMapping> {
        //let map = 0;
        //self.atomic_mem().unwrap().memory().
        Ok(self.mem)
    }
}*/

use core::mem::size_of;
use std::{
    convert,
    io::{self, Read, Result as IoResult, Write},
    path::Path,
    sync::Arc,
};

use anyhow::Result as anyResult;
use log::{debug, error, warn};
use ref_cast::RefCast;
use vhost::vhost_user::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_media::{
    devices::V4l2ProxyDevice, protocol::{V4l2Event, SgEntry}, VirtioMediaDevice, VirtioMediaDeviceRunner,
    VirtioMediaEventQueue, VirtioMediaGuestMemoryMapper,
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

use crate::ThisError;

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

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;
const COMMAND_Q: u16 = 0;
const EVENT_Q: u16 = 1;

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
    event_idx: bool,
    config: VirtioMediaConfig,
    //pub threads: Vec<Mutex<VhostUserMediaThread>>,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    vrings: Vec<VringRwLock>,
    //backend: V4l2ProxyDevice,
}

impl VuMediaBackend {
    /// Create a new virtio video device for /dev/video<num>.
    pub fn new(video_path: &Path) -> Result<Self> {
        Ok(Self {
            event_idx: false,
            config: VirtioMediaConfig {
                device_caps: 0x00001000.into(),
                device_type: 0.into(),
                card: [0; VIRTIO_V4L2_CARD_NAME_LEN],
            },
            //threads: vec![Mutex::new(VhostUserMediaThread::new(backend.clone())?)],
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuMediaError::EventFdError)?,
            mem: None,
            vrings: Vec::new(),
        })
    }

    pub fn process_requests(
        &mut self,
        requests: Vec<DescriptorChainMemory>,
        vring: &VringRwLock,
    ) -> Result<()> {
        if requests.is_empty() {
            warn!("returns empty");
            return Ok(());
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            if descriptors.len() != 2 {
                return Err(VuMediaError::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_request = descriptors[0];
            /*if desc_request.is_write_only() {
                return Err(VuMediaError::UnexpectedWriteOnlyDescriptor(0));
            }*/

            let read_desc_len: usize = desc_request.len() as usize;
            //let header_size = u32::size;
            /*if read_desc_len < header_size {
                return Err(VuMediaError::UnexpectedMinimumDescriptorSize(
                    header_size,
                    read_desc_len,
                ));
            }*/

            let header = desc_chain
                .memory()
                .read_obj::<u32>(desc_request.addr())
                .map_err(|_| VuMediaError::DescriptorReadFailed)?;
            //let mut scmi_request = ScmiRequest::new(header);
            //let n_parameters = self.scmi_handler.number_of_parameters(&scmi_request);
            //debug!("SCMI request with n parameters: {:?}", n_parameters);
            /*let value_size = 4;
            if let Some(expected_parameters) = n_parameters {
                if expected_parameters > 0 {
                    let param_bytes = (expected_parameters as usize) * value_size;
                    let total_size = value_size + param_bytes;
                    if read_desc_len != total_size {
                        return Err(VuMediaError::UnexpectedDescriptorSize(
                            total_size,
                            read_desc_len,
                        ));
                    }
                    /*let mut buffer: Vec<u8> = vec![0; header_size + param_bytes];
                    desc_chain
                        .memory()
                        .read_slice(&mut buffer, desc_request.addr())
                        .map_err(|_| VuMediaError::DescriptorReadFailed)?;*/
                    //self.scmi_handler
                    //    .store_parameters(&mut scmi_request, &buffer[header_size..]);
                } else if read_desc_len != value_size {
                    return Err(VuMediaError::UnexpectedDescriptorSize(
                        value_size,
                        read_desc_len,
                    ));
                }
            }*/

            /*debug!("Calling SCMI request handler");
            let mut response = self.scmi_handler.handle(scmi_request);
            debug!("SCMI response: {:?}", response);*/

            let desc_response = descriptors[1];
            if !desc_response.is_write_only() {
                return Err(VuMediaError::UnexpectedReadableDescriptor(1));
            }

            /*let write_desc_len: usize = desc_response.len() as usize;
            if response.len() > write_desc_len {
                error!(
                    "Response of length {} cannot fit into the descriptor size {}",
                    response.len(),
                    write_desc_len
                );
                response = response.communication_error();
                if response.len() > write_desc_len {
                    return Err(VuMediaError::InsufficientDescriptorSize(
                        response.len(),
                        write_desc_len,
                    ));
                }
            }
            desc_chain
                .memory()
                .write_slice(response.as_slice(), desc_response.addr())
                .map_err(|_| VuMediaError::DescriptorWriteFailed)?;

            if vring
                .add_used(desc_chain.head_index(), response.len() as u32)
                .is_err()
            {
                error!("Couldn't return used descriptors to the ring");
            }*/
        }
        Ok(())
    }

    fn atomic_mem(&self) -> Result<&GuestMemoryAtomic<GuestMemoryMmap>> {
        match &self.mem {
            Some(m) => Ok(m),
            None => Err(VuMediaError::NoMemoryConfigured),
        }
    }

    fn process_command_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        debug!("Processing command queue");
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.atomic_mem()?.memory())
            .map_err(|_| VuMediaError::DescriptorNotFound)?
            .collect();
        warn!("vrings {:?}", requests);
        debug!("Requests to process: {}", requests.len());
        self.process_requests(requests, vring)?;
        // Send notification once all the requests are processed
        debug!("Sending processed request notification");
        vring
            .signal_used_queue()
            .map_err(|_| VuMediaError::SendNotificationFailed)?;
        debug!("Processing command queue finished");

        Ok(())
    }

    pub fn process_event_requests(
        &mut self,
        requests: Vec<DescriptorChainMemory>,
        _vring: &VringRwLock,
    ) -> Result<()> {
        // The requests here are notifications from the guest about adding
        // fresh buffers for the used ring. The Linux driver allocates 256
        // buffers for the event queue initially (arriving here in several
        // batches) and then adds a free buffer after each message delivered
        // through the event queue.
        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            debug!(
                "SCMI event request with n descriptors: {}",
                descriptors.len()
            );
            if descriptors.len() != 1 {
                return Err(VuMediaError::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc = descriptors[0];
            if !desc.is_write_only() {
                return Err(VuMediaError::UnexpectedReadableDescriptor(0));
            }
            debug!("SCMI event request avail descriptor length: {}", desc.len());

            //self.event_descriptors.push(desc_chain);
        }
        Ok(())
    }

    fn process_event_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        debug!("Processing event queue");

        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| VuMediaError::DescriptorNotFound)?
            .collect();
        debug!("Requests to process: {}", requests.len());
        match self.process_event_requests(requests, vring) {
            Ok(_) => {
                // Send notification once all the requests are processed
                debug!("Sending processed request notification");
                vring
                    .signal_used_queue()
                    .map_err(|_| VuMediaError::SendNotificationFailed)?;
                debug!("Notification sent");
            }
            Err(err) => {
                warn!("Failed Media request: {}", err);
                return Err(err);
            }
        }
        //self.start_event_queue(vring);
        debug!("Processing event queue finished");
        Ok(())
    }
}

/// VhostUserBackend trait methods
impl VhostUserBackendMut for VuMediaBackend {
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

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
        debug!("Event idx set to: {}", enabled);
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        debug!("Update memory called");
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<()> {
        debug!("Handle event called");
        if evset != EventSet::IN {
            warn!("Non-input event");
            return Err(VuMediaError::HandleEventNotEpollIn.into());
        }
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
                        self.process_command_queue(vring)?;
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

impl VirtioMediaEventQueue for VuMediaBackend {
    fn send_event(&mut self, event: V4l2Event) {
        let eventq = &self.vrings[EVENT_Q as usize];
        let desc_chain = eventq
            .get_mut()
            .get_queue_mut()
            .iter(self.atomic_mem().unwrap().memory())
            .unwrap()
            .collect::<Vec<_>>()
            .pop();
        let desc_chain = match desc_chain {
            Some(desc_chain) => desc_chain,
            None => {
                warn!("No available buffer found in the event queue.");
                return;
            }
        };
        let event = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<V4l2Event>(),
            )
        };
        let descriptors: Vec<_> = desc_chain.clone().collect();
        let desc_response = &descriptors[descriptors.len() - 1];
        if desc_chain
            .memory()
            .write_slice(event, desc_response.addr())
            .is_err()
        {
            warn!("Descriptor write failed");
        }

        if eventq
            .add_used(desc_chain.head_index(), desc_response.len())
            .is_err()
        {
            warn!("Couldn't return used descriptors to the ring");
        }
        eventq.signal_used_queue().unwrap();
    }
}

impl VirtioMediaGuestMemoryMapper for VuMediaBackend {
    type GuestMemoryMapping = GuestMemoryAtomic<GuestMemoryMmap>;

    fn new_mapping(&self, sgs: Vec<SgEntry>) -> anyResult<Self::GuestMemoryMapping> {
        //let map = 0;
        //self.atomic_mem().unwrap().memory().
        Ok(self.mem)
    }
}
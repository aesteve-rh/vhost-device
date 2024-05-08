// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    convert,
    io::{self, Result as IoResult},
    path::Path,
};

use log::{debug, info, warn};
use thiserror::Error as ThisError;
use vhost::vhost_user::{Backend, VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_media::{
    poll::SessionPoller, protocol::VirtioMediaDeviceConfig, VirtioMediaDevice,
    VirtioMediaDeviceRunner,
};
use virtio_queue::QueueOwnedT;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};
use zerocopy::AsBytes;

use crate::{
    media_backends::{EventQueue, VuBackend},
    virtio,
};

pub(crate) type MediaResult<T> = std::result::Result<T, VuMediaError>;
pub(crate) type Writer = virtio::DescriptorChainWriter<GuestMemoryLoadGuard<GuestMemoryMmap>>;
pub(crate) type Reader = virtio::DescriptorChainReader<GuestMemoryLoadGuard<GuestMemoryMmap>>;

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub(crate) enum BackendType {
    #[default]
    Null,
    #[cfg(feature = "simple-device")]
    SimpleCapture,
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
    #[error("Failed to create a used descriptor")]
    AddUsedDescriptorFailed,
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Can't create eventFd")]
    EventFdError,
    #[error("Video device file doesn't exists or can't be accessed")]
    AccessVideoDeviceFile,
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

pub(crate) struct VuMediaBackend<
    D: VirtioMediaDevice<Reader, Writer>,
    F: Fn(EventQueue, VuBackend) -> MediaResult<D>,
> {
    config: VirtioMediaDeviceConfig,
    event_idx: bool,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    pub exit_event: EventFd,
    vu_req: Option<Backend>,
    worker: Option<VirtioMediaDeviceRunner<Reader, Writer, D, ()>>,
    create_device: F,
}

impl<D, F> VuMediaBackend<D, F>
where
    D: VirtioMediaDevice<Reader, Writer>,
    F: Fn(EventQueue, VuBackend) -> MediaResult<D>,
{
    /// Create a new virtio video device for /dev/video<num>.
    pub fn new(
        _video_path: &Path,
        config: VirtioMediaDeviceConfig,
        create_device: F,
    ) -> MediaResult<Self> {
        Ok(Self {
            event_idx: false,
            mem: None,
            config,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuMediaError::EventFdError)?,
            vu_req: None,
            worker: None,
            create_device,
        })
    }

    fn atomic_mem(&self) -> MediaResult<&GuestMemoryAtomic<GuestMemoryMmap>> {
        match &self.mem {
            Some(m) => Ok(m),
            None => Err(VuMediaError::NoMemoryConfigured),
        }
    }

    fn process_command_queue(&mut self, vring: &VringRwLock) -> MediaResult<()> {
        let chains: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.atomic_mem()?.memory())
            .map_err(|_| VuMediaError::DescriptorNotFound)?
            .collect();

        for dc in chains {
            let mut writer = Writer::new(dc.clone());
            let mut reader = Reader::new(dc.clone());

            if let Some(runner) = &mut self.worker {
                runner.handle_command(&mut reader, &mut writer);
            }

            vring
                .add_used(dc.head_index(), writer.max_written())
                .map_err(|_| VuMediaError::AddUsedDescriptorFailed)?;
        }

        vring
            .signal_used_queue()
            .map_err(|_| VuMediaError::SendNotificationFailed)?;

        Ok(())
    }
}

/// VhostUserBackend trait methods
impl<D, F> VhostUserBackendMut for VuMediaBackend<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    <D as VirtioMediaDevice<Reader, Writer>>::Session: Send + Sync,
    F: Fn(EventQueue, VuBackend) -> MediaResult<D> + Send + Sync,
{
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
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
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::BACKEND_REQ
            | VhostUserProtocolFeatures::BACKEND_SEND_FD
            | VhostUserProtocolFeatures::REPLY_ACK
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        info!("Memory updated - guest probably booting");
        self.mem = Some(atomic_mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<()> {
        if evset != EventSet::IN {
            warn!("Non-input event");
            return Err(VuMediaError::HandleEventNotEpollIn.into());
        }
        let eventq = &vrings[EVENT_Q as usize];
        if self.worker.is_none() {
            let device = (self.create_device)(
                EventQueue {
                    mem: self.mem.as_ref().unwrap().clone(),
                    queue: eventq.clone(),
                },
                VuBackend::new(self.vu_req.as_ref().unwrap().clone()),
            )
            .unwrap();
            self.worker = Some(VirtioMediaDeviceRunner::new(device, ()));
        }

        match device_event {
            COMMAND_Q => {
                let commandq = &vrings[COMMAND_Q as usize];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        commandq.disable_notification().unwrap();
                        self.process_command_queue(commandq)?;
                        if !commandq.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_command_queue(commandq)?;
                }
            }

            EVENT_Q => {
                // This queue is used by the device to asynchronously send
                // event notifications to the driver. Thus, we do not handle
                // incoming events.
                warn!("Unexpected event notification received");
            }

            _ => {
                warn!("unhandled device_event: {}", device_event);
                return Err(VuMediaError::HandleUnknownEvent.into());
            }
        }
        Ok(())
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        let offset = _offset as usize;
        let size = _size as usize;

        let buf = self.config.as_bytes();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        debug!("Exit event called");
        self.exit_event.try_clone().ok()
    }

    fn set_backend_req_fd(&mut self, vu_req: Backend) {
        debug!("Setting req fd");
        self.vu_req = Some(vu_req);
    }
}

// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod null;

use std::{os::fd::BorrowedFd, path::Path};

use log::warn;
use null::NullBackend;
use vhost::vhost_user::{
    message::{VhostUserBackendMapMsg, VhostUserFSBackendMsgFlags},
    Backend, VhostUserFrontendReqHandler,
};
use vhost_user_backend::{VringRwLock, VringT};
//#[cfg(feature = "simple-device")]
use virtio_media::{
    protocol::{DequeueBufferEvent, ErrorEvent, SessionEvent, V4l2Event},
    VirtioMediaEventQueue, VirtioMediaHostMemoryMapper,
};
use virtio_queue::QueueOwnedT;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};

use crate::vhu_media::{BackendType, MediaResult, VuMediaError};

#[repr(C)]
pub struct EventQueue {
    pub queue: VringRwLock,
    /// Guest memory map.
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
}

impl VirtioMediaEventQueue for EventQueue {
    fn send_event(&mut self, event: V4l2Event) {
        let eventq = &self.queue;
        let desc_chain = eventq
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.memory())
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
        let descriptors: Vec<_> = desc_chain.clone().collect();
        if desc_chain
            .memory()
            .write_slice(
                match event {
                    V4l2Event::Error(event) => unsafe {
                        std::slice::from_raw_parts(
                            &event as *const _ as *const u8,
                            std::mem::size_of::<ErrorEvent>(),
                        )
                    },
                    V4l2Event::DequeueBuffer(event) => unsafe {
                        std::slice::from_raw_parts(
                            &event as *const _ as *const u8,
                            std::mem::size_of::<DequeueBufferEvent>(),
                        )
                    },
                    V4l2Event::Event(event) => unsafe {
                        std::slice::from_raw_parts(
                            &event as *const _ as *const u8,
                            std::mem::size_of::<SessionEvent>(),
                        )
                    },
                },
                descriptors[0].addr(),
            )
            .is_err()
        {
            warn!("Failed to write event");
            return;
        }

        if eventq
            .add_used(desc_chain.head_index(), descriptors[0].len())
            .is_err()
        {
            warn!("Couldn't return used descriptors to the ring");
        }
        if let Err(e) = eventq.signal_used_queue() {
            warn!("Failed to signal used queue: {e}")
        }
    }
}

#[derive(Debug, Default)]
pub struct AddressRange {
    offset: u64,
    length: u64,
}

pub struct VuBackend {
    backend: Backend,
    address: Vec<AddressRange>,
}

impl VuBackend {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            address: Vec::new(),
        }
    }
}

impl VirtioMediaHostMemoryMapper for VuBackend {
    fn add_mapping(
        &mut self,
        buffer: BorrowedFd,
        length: u64,
        offset: u64,
        rw: bool,
    ) -> std::result::Result<u64, i32> {
        let mut msg: VhostUserBackendMapMsg = Default::default();
        msg.shm_offset = offset;
        msg.len = length;
        msg.flags = if rw {
            VhostUserFSBackendMsgFlags::MAP_W | VhostUserFSBackendMsgFlags::MAP_R
        } else {
            VhostUserFSBackendMsgFlags::MAP_R
        };

        self.address.push(AddressRange {
            offset: msg.shm_offset,
            length: msg.len,
        });
        if let Err(e) = self.backend.mem_backend_map(&msg, &buffer) {
            warn!("failed to map memory buffer {}", e);
            return Err(libc::EINVAL);
        }

        Ok(offset)
    }

    fn remove_mapping(&mut self, shm_offset: u64) -> std::result::Result<(), i32> {
        let mut msg: VhostUserBackendMapMsg = Default::default();
        msg.shm_offset = shm_offset;

        match self.address.iter().position(|a| a.offset == msg.shm_offset) {
            Some(index) => {
                let addr = self.address.swap_remove(index);
                msg.len = addr.length;
                self.backend
                    .mem_backend_unmap(&msg)
                    .map_err(|_| libc::EINVAL)?;
            }
            None => return Err(libc::EINVAL),
        };

        Ok(())
    }
}

pub trait MediaBackend {}

pub(crate) fn alloc_media_backend(
    backend: BackendType,
    video_path: &Path,
) -> MediaResult<Box<dyn MediaBackend + Sync + Send>> {
    macro_rules! build_backend {
        ($type:ident) => {
            Box::new($type::new(video_path).map_err(|_| VuMediaError::AccessVideoDeviceFile)?)
        };
    }
    Ok(match backend {
        BackendType::Null => build_backend!(NullBackend),
        #[cfg(feature = "simple-device")]
        BackendType::SimpleCapture => SimpleCaptureDevice::new(event_queue, host_mapper),
    })
}

// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use log::warn;
use vhost_user_backend::{VringRwLock, VringT};
use virtio_media::{
    devices::SimpleCaptureDevice,
    protocol::{DequeueBufferEvent, ErrorEvent, SessionEvent, V4l2Event},
    VirtioMediaEventQueue,
};
use virtio_queue::QueueOwnedT;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};

use crate::vhu_media::{DescriptorChainMemory, Result, EVENT_Q};

#[repr(C)]
struct EventQueue {
    queue: VringRwLock,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
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

pub(crate) struct VhostUserMediaThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    backend: Option<Arc<Mutex<SimpleCaptureDevice<EventQueue>>>>,
}

impl VhostUserMediaThread {
    pub fn new(video_path: &Path) -> Result<Self> {
        Ok(Self {
            mem: None,
            backend: None,
        })
    }

    pub fn process_requests(
        &mut self,
        requests: Vec<DescriptorChainMemory>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }
        if self.backend.is_none() {
            self.backend = Some(Arc::new(Mutex::new(&mut SimpleCaptureDevice::new(
                EventQueue {
                    mem: self.mem.unwrap(),
                    queue: self.vrings[EVENT_Q as usize],
                },
            ))));
        }
    }
}

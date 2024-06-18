// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
mod media_backends;
mod vhu_media;
mod vhu_media_thread;
mod virtio;

use std::{path::PathBuf, sync::Arc};

use ::virtio_media::protocol::VirtioMediaDeviceConfig;
use clap::Parser;
use log::debug;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vhu_media::{BackendType, VuMediaBackend};
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) const VIRTIO_V4L2_CARD_NAME_LEN: usize = 32;

#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_media::VuMediaError),
    //#[error("Could not create daemon: {0}")]
    //CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Clone, Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct MediaArgs {
    /// Unix socket to which a hypervisor connects to and sets up the control
    /// path with the device.
    #[clap(short, long)]
    socket_path: PathBuf,

    /// Path to the media device file. Defaults to /dev/video0.
    #[clap(short = 'd', long, default_value = "/dev/video0")]
    v4l2_device: PathBuf,

    /// Media backend to be used.
    #[clap(short, long, default_value = "simple-capture")]
    #[clap(value_enum)]
    backend: BackendType,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VuMediaConfig {
    pub socket_path: PathBuf,
    pub v4l2_device: PathBuf,
    pub backend: BackendType,
}

impl From<MediaArgs> for VuMediaConfig {
    fn from(args: MediaArgs) -> Self {
        // Divide available bandwidth by the number of threads in order
        // to avoid overwhelming the HW.
        Self {
            socket_path: args.socket_path.to_owned(),
            v4l2_device: args.v4l2_device.to_owned(),
            backend: args.backend,
        }
    }
}

fn create_simple_capture_device_config() -> VirtioMediaDeviceConfig {
    use v4l2r::ioctl::Capabilities;
    let mut card = [0u8; VIRTIO_V4L2_CARD_NAME_LEN];
    let card_name = "simple_device";
    card[0..card_name.len()].copy_from_slice(card_name.as_bytes());
    VirtioMediaDeviceConfig {
        device_caps: (Capabilities::VIDEO_CAPTURE | Capabilities::STREAMING).bits(),
        device_type: 0,
        card,
    }
}

fn create_v4l2_proxy_device_config(device_path: &PathBuf) -> VirtioMediaDeviceConfig {
    use virtio_media::v4l2r::ioctl::Capabilities;

    let device = virtio_media::v4l2r::device::Device::open(
        device_path.as_ref(),
        virtio_media::v4l2r::device::DeviceConfig::new().non_blocking_dqbuf(),
    )
    .unwrap();
    let mut device_caps = device.caps().device_caps();

    // We are only exposing one device worth of capabilities.
    device_caps.remove(Capabilities::DEVICE_CAPS);

    // Read-write is not supported by design.
    device_caps.remove(Capabilities::READWRITE);

    let mut config = VirtioMediaDeviceConfig {
        device_caps: device_caps.bits(),
        // VFL_TYPE_VIDEO
        // TODO should not be hardcoded!
        device_type: 0,
        card: Default::default(),
    };
    let card = &device.caps().card;
    let name_slice = card[0..std::cmp::min(card.len(), config.card.len())].as_bytes();
    config.card.as_mut_slice()[0..name_slice.len()].copy_from_slice(name_slice);

    debug!("Device config: {:?}", config);

    config
}

pub(crate) fn start_backend(media_config: VuMediaConfig) -> Result<()> {
    loop {
        debug!("Starting backend");
        //let config = create_simple_capture_device_config();
        let path = media_config.v4l2_device.clone();
        let config = create_v4l2_proxy_device_config(&path);
        let vu_media_backend = Arc::new(
            VuMediaBackend::new(
                media_config.v4l2_device.as_path(),
                config,
                move |event_queue, guest_mapper, host_mapper| {
                    /*Ok(match media_config.backend {
                        BackendType::SimpleCapture => {
                            virtio_media::devices::SimpleCaptureDevice::new(
                                event_queue,
                                host_mapper,
                            )
                        },
                        BackendType::V4l2Proxy => {
                            virtio_media::devices::V4l2ProxyDevice::new(
                                media_config.v4l2_device.as_path(),
                                event_queue,
                                guest_mapper,
                                host_mapper,
                            )
                        },
                    })*/
                    Ok(virtio_media::devices::V4l2ProxyDevice::new(
                        path.clone(),
                        event_queue,
                        guest_mapper,
                        host_mapper,
                    ))
                },
            )
            .map_err(Error::CouldNotCreateBackend)?,
        );
        let mut daemon = VhostUserDaemon::new(
            "vhost-device-media".to_owned(),
            vu_media_backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let mut vring_workers = daemon.get_epoll_handlers();
        for thread in vu_media_backend.threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_workers(vring_workers.remove(0));
        }

        daemon
            .serve(&media_config.socket_path)
            .map_err(Error::ServeFailed)?;
        debug!("Finishing backend");
    }
}

fn main() -> Result<()> {
    env_logger::init();

    start_backend(VuMediaConfig::from(MediaArgs::parse()))
}

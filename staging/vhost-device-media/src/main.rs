// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
mod vhu_media;
mod vhu_media_thread;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::Parser;
use log::debug;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vhu_media::VuMediaBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub(crate) type Result<T> = std::result::Result<T, Error>;

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

    /// Path to the media device file. Defaults to /dev/media0.
    #[clap(short = 'd', long, default_value = "/dev/media0")]
    v4l2_device: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VuMediaConfig {
    pub socket_path: PathBuf,
    pub v4l2_device: PathBuf,
}

impl From<MediaArgs> for VuMediaConfig {
    fn from(args: MediaArgs) -> Self {
        // Divide available bandwidth by the number of threads in order
        // to avoid overwhelming the HW.
        Self {
            socket_path: args.socket_path.to_owned(),
            v4l2_device: args.v4l2_device.to_owned(),
        }
    }
}

pub(crate) fn start_backend(config: VuMediaConfig) -> Result<()> {
    loop {
        debug!("Starting backend");
        let vu_video_backend = Arc::new(RwLock::new(
            VuMediaBackend::new(config.v4l2_device.as_path())
                .map_err(Error::CouldNotCreateBackend)?,
        ));

        let mut daemon = VhostUserDaemon::new(
            "vhost-device-media".to_owned(),
            vu_video_backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        daemon
            .serve(&config.socket_path)
            .map_err(Error::ServeFailed)?;
        debug!("Finishing backend");
    }
}

fn main() -> Result<()> {
    env_logger::init();

    start_backend(VuMediaConfig::from(MediaArgs::parse()))
}

// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{io, path::Path};

use super::MediaBackend;

pub struct NullBackend;

impl MediaBackend for NullBackend {}

impl NullBackend {
    pub fn new(video_path: &Path) -> io::Result<Self> {
        // Check if file exists
        std::fs::File::create(video_path)?;
        Ok(Self)
    }
}

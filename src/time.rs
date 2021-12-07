//! Helpers for time.

/// A type which can return the duration since the epoch.
pub trait DurationSinceEpoch {
    /// Returns the number of seconds since the epoch.
    fn as_secs(&self) -> u64;
}

use std::time::{Duration, SystemTime};

/// Duration since the epoch represented by standard library types.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct StdDurationSinceEpoch(Duration);

impl StdDurationSinceEpoch {
    /// Returns the current duration since the epoch.
    pub fn now() -> Self {
        StdDurationSinceEpoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("SystemTime should be later than UNIX_EPOCH."),
        )
    }
}

impl DurationSinceEpoch for StdDurationSinceEpoch {
    fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }
}

#[cfg(feature = "web_crypto")]
use js_sys::Date;

#[cfg(feature = "web_crypto")]
#[derive(Clone, Copy, Debug)]
pub struct JsDurationSinceEpoch(f64);

#[cfg(feature = "web_crypto")]
impl JsDurationSinceEpoch {
    pub fn now() -> Self {
        Self(Date::now())
    }
}

#[cfg(feature = "web_crypto")]
impl DurationSinceEpoch for JsDurationSinceEpoch {
    fn as_secs(&self) -> u64 {
        (self.0 / 1000.0) as u64
    }
}

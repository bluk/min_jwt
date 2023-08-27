//! Helpers for time.

/// A type which can return the duration since the epoch.
pub trait DurationSinceEpoch {
    /// Returns the number of seconds since the epoch.
    fn as_secs(&self) -> u64;
}

#[cfg(feature = "std")]
/// Duration since the epoch represented by standard library types.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct StdDurationSinceEpoch(core::time::Duration);

#[cfg(feature = "std")]
impl StdDurationSinceEpoch {
    /// Returns the current duration since the epoch.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn now() -> Self {
        use std::time::SystemTime;

        StdDurationSinceEpoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("SystemTime should be later than UNIX_EPOCH."),
        )
    }
}

#[cfg(feature = "std")]
impl DurationSinceEpoch for StdDurationSinceEpoch {
    fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }
}

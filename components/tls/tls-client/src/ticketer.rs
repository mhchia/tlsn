use instant::{Duration, SystemTime};

/// The timebase for expiring and rolling tickets and ticketing
/// keys.  This is UNIX wall time in seconds.
///
/// This is guaranteed to be on or after the UNIX epoch.
#[derive(Clone, Copy, Debug)]
pub struct TimeBase(Duration);

impl TimeBase {
    #[inline]
    pub fn now() -> Result<Self, ()> {
        Ok(Self(
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?,
        ))
    }

    #[inline]
    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }
}

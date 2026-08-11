use std::fmt;

/// The model variants exposed by the C# and native Xdows-Model invokers.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ModelMode {
    /// Full Standard feature extraction and inference.
    #[default]
    Standard = 0,
    /// Low-latency Flash inference.
    Flash = 1,
    /// Pro hybrid or stacking inference.
    Pro = 2,
    /// Flash-to-Standard-to-Pro adaptive inference.
    Adaptive = 3,
}

impl ModelMode {
    /// Returns the stable integer representation used by the native ABI.
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for ModelMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Standard => "Standard",
            Self::Flash => "Flash",
            Self::Pro => "Pro",
            Self::Adaptive => "Adaptive",
        })
    }
}

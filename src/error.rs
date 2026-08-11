use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path::PathBuf;

/// A result returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Status codes defined by `xdows_model_native.h`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeStatus {
    /// The operation completed successfully.
    Ok,
    /// An argument passed across the ABI was invalid.
    InvalidArgument,
    /// The file selected for scanning does not exist.
    FileNotFound,
    /// The selected file type is not supported.
    UnsupportedFile,
    /// One or more model files could not be found.
    ModelNotFound,
    /// The native inference implementation failed.
    InternalError,
    /// A status from a newer native library that this crate does not know yet.
    Unknown(i32),
}

impl NativeStatus {
    /// Converts the integer ABI representation into a typed status.
    pub const fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::InvalidArgument,
            2 => Self::FileNotFound,
            3 => Self::UnsupportedFile,
            4 => Self::ModelNotFound,
            5 => Self::InternalError,
            value => Self::Unknown(value),
        }
    }

    /// Returns the integer value used by the native ABI.
    pub const fn code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::InvalidArgument => 1,
            Self::FileNotFound => 2,
            Self::UnsupportedFile => 3,
            Self::ModelNotFound => 4,
            Self::InternalError => 5,
            Self::Unknown(value) => value,
        }
    }
}

impl fmt::Display for NativeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => formatter.write_str("ok"),
            Self::InvalidArgument => formatter.write_str("invalid argument"),
            Self::FileNotFound => formatter.write_str("file not found"),
            Self::UnsupportedFile => formatter.write_str("unsupported file"),
            Self::ModelNotFound => formatter.write_str("model not found"),
            Self::InternalError => formatter.write_str("internal native error"),
            Self::Unknown(code) => write!(formatter, "unknown native status {code}"),
        }
    }
}

/// An error produced while loading or invoking Xdows-Model.
#[derive(Debug)]
pub enum Error {
    /// The native bridge is only available on Windows.
    UnsupportedPlatform,
    /// A path could not be represented as a Windows UTF-16 string.
    InvalidPath {
        /// The rejected path.
        path: PathBuf,
        /// Why the path was rejected.
        reason: &'static str,
    },
    /// A filesystem operation failed.
    Io {
        /// The operation being attempted.
        operation: &'static str,
        /// The path involved in the operation.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// Windows could not load the native library.
    LibraryLoad {
        /// The library path.
        path: PathBuf,
        /// The value returned by `GetLastError`.
        windows_error: u32,
    },
    /// The loaded library does not export a required ABI function.
    MissingSymbol {
        /// The missing exported function.
        symbol: &'static str,
        /// The value returned by `GetLastError`.
        windows_error: u32,
    },
    /// A native operation returned a failure status.
    NativeCall {
        /// The native operation being attempted.
        operation: &'static str,
        /// The typed native status.
        status: NativeStatus,
        /// An optional diagnostic allocated by the native library.
        message: Option<String>,
    },
    /// The native library returned data that violates its ABI contract.
    InvalidNativeResult(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("Xdows-Model native invocation is only supported on Windows")
            }
            Self::InvalidPath { path, reason } => {
                write!(formatter, "invalid path '{}': {reason}", path.display())
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} '{}': {source}",
                path.display()
            ),
            Self::LibraryLoad {
                path,
                windows_error,
            } => write!(
                formatter,
                "failed to load native library '{}' (Windows error {windows_error})",
                path.display()
            ),
            Self::MissingSymbol {
                symbol,
                windows_error,
            } => write!(
                formatter,
                "native library is missing export '{symbol}' (Windows error {windows_error})"
            ),
            Self::NativeCall {
                operation,
                status,
                message,
            } => {
                write!(formatter, "native {operation} failed: {status}")?;
                if let Some(message) = message {
                    write!(formatter, " ({message})")?;
                }
                Ok(())
            }
            Self::InvalidNativeResult(reason) => {
                write!(
                    formatter,
                    "native library returned an invalid scan result: {reason}"
                )
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

//! Safe Rust bindings for the native Xdows-Model inference library.
//!
//! The API follows the lifecycle of the C# `ModelInvoker`: load the runtime,
//! initialize one model mode, scan any number of files, and let the session
//! unload automatically when it is dropped.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod error;
mod ffi;
mod mode;
mod models;
mod session;

pub use error::{Error, NativeStatus, Result};
pub use mode::ModelMode;
pub use models::{for_mode as models_for_mode, ModelAsset};
pub use session::{ModelInvoker, ModelLibrary, ScanResult, ScanVerdict, Thresholds};

/// The file name exported by the Xdows-Model native project.
pub const NATIVE_LIBRARY_FILE_NAME: &str = "Xdows-Model-Native.dll";

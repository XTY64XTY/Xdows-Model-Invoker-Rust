use crate::ffi::{canonical_library_path, encode_path, NativeApi, RawScanResult};
use crate::{Error, ModelMode, NativeStatus, Result, NATIVE_LIBRARY_FILE_NAME};
use std::cell::Cell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

/// A loaded `Xdows-Model-Native.dll` and its validated function table.
///
/// Cloning this value is inexpensive. The DLL remains loaded until the final
/// library handle and all model sessions have been dropped.
#[derive(Clone)]
pub struct ModelLibrary {
    api: Arc<NativeApi>,
    path: Arc<PathBuf>,
}

impl ModelLibrary {
    /// Loads a native Xdows-Model library from an explicit path.
    ///
    /// The path is canonicalized before `LoadLibraryExW` is called. Dependency
    /// lookup is restricted to the DLL directory and the standard safe Windows
    /// search directories.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        #[cfg(not(windows))]
        {
            let _ = path;
            return Err(Error::UnsupportedPlatform);
        }

        #[cfg(windows)]
        {
            let path = canonical_library_path(path.as_ref())?;
            let api = NativeApi::load(&path)?;
            Ok(Self {
                api: Arc::new(api),
                path: Arc::new(path),
            })
        }
    }

    /// Loads `Xdows-Model-Native.dll` from a deployment directory.
    pub fn load_from_directory(directory: impl AsRef<Path>) -> Result<Self> {
        Self::load(directory.as_ref().join(NATIVE_LIBRARY_FILE_NAME))
    }

    /// Returns the canonical path of the loaded native library.
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }
}

/// A successful Xdows-Model scan.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanResult {
    /// Whether the selected model classified the file as a threat.
    pub is_threat: bool,
    /// Threat probability in the inclusive `0.0..=100.0` range.
    pub probability: f32,
    /// The optional detection name produced for a threat.
    pub detection_name: Option<String>,
}

/// An initialized Xdows-Model session.
///
/// A session owns one native inference context and can scan multiple files.
/// It is movable between threads but deliberately not shareable between them;
/// create one session per worker when scans need to run concurrently.
pub struct ModelInvoker {
    library: ModelLibrary,
    session: NonNull<c_void>,
    mode: ModelMode,
    _not_sync: PhantomData<Cell<()>>,
}

impl ModelInvoker {
    /// Initializes one of the four Xdows-Model modes.
    ///
    /// `model_directory` must contain the model files required by `mode`. When
    /// it is `None`, the native library checks its own directory and then the
    /// current working directory, matching the native Xdows-Model contract.
    pub fn initialize(
        library: &ModelLibrary,
        mode: ModelMode,
        model_directory: Option<&Path>,
    ) -> Result<Self> {
        let encoded_directory = model_directory.map(encode_path).transpose()?;
        let directory_pointer = encoded_directory
            .as_ref()
            .map_or(std::ptr::null(), |value| value.as_ptr());
        let mut raw_session = std::ptr::null_mut();
        let status = unsafe {
            library.api.initialize(
                directory_pointer,
                mode.as_raw(),
                &mut raw_session as *mut *mut c_void,
            )
        };
        let status = NativeStatus::from_code(status);
        if status != NativeStatus::Ok {
            return Err(Error::NativeCall {
                operation: "initialize",
                status,
                message: None,
            });
        }

        let session = NonNull::new(raw_session).ok_or(Error::InvalidNativeResult(
            "initialize returned a null session",
        ))?;
        Ok(Self {
            library: library.clone(),
            session,
            mode,
            _not_sync: PhantomData,
        })
    }

    /// Initializes Standard mode.
    pub fn standard(library: &ModelLibrary, model_directory: Option<&Path>) -> Result<Self> {
        Self::initialize(library, ModelMode::Standard, model_directory)
    }

    /// Initializes Flash mode.
    pub fn flash(library: &ModelLibrary, model_directory: Option<&Path>) -> Result<Self> {
        Self::initialize(library, ModelMode::Flash, model_directory)
    }

    /// Initializes Pro mode.
    pub fn pro(library: &ModelLibrary, model_directory: Option<&Path>) -> Result<Self> {
        Self::initialize(library, ModelMode::Pro, model_directory)
    }

    /// Initializes Adaptive mode.
    pub fn adaptive(library: &ModelLibrary, model_directory: Option<&Path>) -> Result<Self> {
        Self::initialize(library, ModelMode::Adaptive, model_directory)
    }

    /// Returns the mode selected when this session was initialized.
    pub const fn mode(&self) -> ModelMode {
        self.mode
    }

    /// Scans a file using the already initialized model session.
    pub fn scan_file(&self, file_path: impl AsRef<Path>) -> Result<ScanResult> {
        let encoded_path = encode_path(file_path.as_ref())?;
        let mut raw_result = RawScanResult::default();
        let call_status = unsafe {
            self.library.api.scan_file(
                self.session.as_ptr(),
                encoded_path.as_ptr(),
                &mut raw_result,
            )
        };

        let detection_name = unsafe {
            self.library
                .api
                .copy_and_free_string(raw_result.detection_name)
        };
        let error_message = unsafe {
            self.library
                .api
                .copy_and_free_string(raw_result.error_message)
        };

        let call_status = NativeStatus::from_code(call_status);
        if call_status != NativeStatus::Ok {
            return Err(Error::NativeCall {
                operation: "scan",
                status: call_status,
                message: error_message,
            });
        }

        let result_status = NativeStatus::from_code(raw_result.status);
        if result_status != NativeStatus::Ok {
            return Err(Error::NativeCall {
                operation: "scan",
                status: result_status,
                message: error_message,
            });
        }
        if raw_result.is_threat != 0 && raw_result.is_threat != 1 {
            return Err(Error::InvalidNativeResult("IsThreat is not 0 or 1"));
        }
        if !raw_result.probability.is_finite() || !(0.0..=100.0).contains(&raw_result.probability) {
            return Err(Error::InvalidNativeResult(
                "Probability is not a finite percentage",
            ));
        }

        Ok(ScanResult {
            is_threat: raw_result.is_threat == 1,
            probability: raw_result.probability,
            detection_name,
        })
    }
}

// The native session is uniquely owned and has no thread affinity. It is not
// Sync, so callers cannot scan the same native session concurrently.
unsafe impl Send for ModelInvoker {}

impl Drop for ModelInvoker {
    fn drop(&mut self) {
        unsafe {
            self.library.api.shutdown(self.session.as_ptr());
        }
    }
}

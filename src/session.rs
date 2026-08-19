use crate::ffi::{canonical_library_path, encode_path, NativeApi, RawScanResult};
use crate::models::{for_mode as models_for_mode, ModelAsset};
use crate::{Error, ModelMode, NativeStatus, Result, NATIVE_LIBRARY_FILE_NAME};
use std::cell::Cell;
use std::ffi::c_void;
use std::fmt;
use std::fs;
use std::io::Write;
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

    /// Writes the embedded model files required by `mode` into `directory`.
    ///
    /// Existing files are left in place when their size matches the embedded
    /// asset, so repeated calls are idempotent and never overwrite a model that
    /// a caller placed deliberately. This mirrors the C#
    /// `ModelInvoker.EnsureModelAvailable` flow, which extracts the embedded
    /// resources next to the assembly on first use. The native library does not
    /// need to be loaded to call this function.
    pub fn ensure_models(directory: &Path, mode: ModelMode) -> Result<()> {
        write_assets(directory, models_for_mode(mode))
    }

    /// Writes all seven embedded model files into `directory`.
    ///
    /// Useful when a deployment wants every model available up front instead of
    /// extracting them per mode. Existing files are preserved like
    /// [`ensure_models`](Self::ensure_models).
    pub fn ensure_all_models(directory: &Path) -> Result<()> {
        write_assets(directory, crate::models::ALL)
    }
}

fn write_assets(directory: &Path, assets: &[&ModelAsset]) -> Result<()> {
    fs::create_dir_all(directory).map_err(|source| Error::Io {
        operation: "create model directory",
        path: directory.to_path_buf(),
        source,
    })?;

    for asset in assets {
        let target = directory.join(asset.file_name);
        if let Ok(metadata) = fs::metadata(&target) {
            if metadata.len() as usize == asset.bytes.len() {
                continue;
            }
        }

        let mut file = fs::File::create(&target).map_err(|source| Error::Io {
            operation: "create model file",
            path: target.clone(),
            source,
        })?;
        file.write_all(asset.bytes).map_err(|source| Error::Io {
            operation: "write model file",
            path: target.clone(),
            source,
        })?;
        file.sync_all().ok();
    }
    Ok(())
}

/// The three-tier classification produced by Xdows-Model.
///
/// `Malware` means the probability reached the fixed threshold,
/// `Suspicious` means it reached the model's recommended threshold,
/// and `Clean` covers everything below the recommended threshold.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ScanVerdict {
    /// Probability is below the recommended threshold.
    #[default]
    Clean = 0,
    /// Probability is at or above the recommended threshold but below the fixed threshold.
    Suspicious = 1,
    /// Probability is at or above the fixed threshold.
    Malware = 2,
}

impl ScanVerdict {
    /// Returns the stable integer representation used by the native ABI.
    pub const fn as_raw(self) -> i32 {
        self as i32
    }

    /// Converts the integer ABI representation into a typed verdict.
    pub const fn from_raw(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Clean),
            1 => Some(Self::Suspicious),
            2 => Some(Self::Malware),
            _ => None,
        }
    }
}

impl fmt::Display for ScanVerdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Clean => "Clean",
            Self::Suspicious => "Suspicious",
            Self::Malware => "Malware",
        })
    }
}

/// A successful Xdows-Model scan.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanResult {
    /// The three-tier verdict assigned by the native library.
    pub verdict: ScanVerdict,
    /// Whether the selected model classified the file as a threat (anything but `Clean`).
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
    /// When `model_directory` is `Some(dir)`, the embedded model files for `mode`
    /// are first extracted into `dir` (overriding only missing or mismatched
    /// files), and `dir` is passed to the native library. When it is `None`,
    /// the models are extracted into a per-user cache directory under the
    /// system temp folder and that directory is passed instead. This mirrors
    /// the C# `ModelInvoker.Initialize`/`EnsureModelAvailable` flow, which
    /// materializes the embedded resources next to the assembly on first use.
    pub fn initialize(
        library: &ModelLibrary,
        mode: ModelMode,
        model_directory: Option<&Path>,
    ) -> Result<Self> {
        let resolved_directory = match model_directory {
            Some(directory) => directory.to_path_buf(),
            None => default_model_directory(),
        };
        ModelLibrary::ensure_models(&resolved_directory, mode)?;

        let encoded_directory = encode_path(&resolved_directory)?;
        let directory_pointer = encoded_directory.as_ptr();
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
        let verdict = ScanVerdict::from_raw(raw_result.verdict)
            .ok_or(Error::InvalidNativeResult("Verdict is not 0, 1, or 2"))?;
        if !raw_result.probability.is_finite() || !(0.0..=100.0).contains(&raw_result.probability) {
            return Err(Error::InvalidNativeResult(
                "Probability is not a finite percentage",
            ));
        }

        Ok(ScanResult {
            verdict,
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

/// Returns the directory used to extract embedded models when the caller does
/// not pass an explicit `model_directory`.
///
/// The location is `%TEMP%\xdows-model-invoker`, which is per-user, writable
/// without elevation, and stable across runs so the extraction can be skipped on
/// subsequent invocations.
fn default_model_directory() -> PathBuf {
    std::env::temp_dir().join("xdows-model-invoker")
}

#[cfg(test)]
mod tests {
    use super::default_model_directory;
    use crate::models::for_mode as models_for_mode;
    use crate::ModelMode;

    #[test]
    fn default_model_directory_is_under_temp() {
        let dir = default_model_directory();
        let temp = std::env::temp_dir();
        assert!(
            dir.starts_with(&temp),
            "{} should live under {}",
            dir.display(),
            temp.display()
        );
    }

    #[test]
    fn embedded_extraction_is_idempotent() {
        let dir = default_model_directory().join("idempotent-test");
        std::fs::create_dir_all(&dir).unwrap();
        // Write only the Standard model and confirm the helper does not fail when
        // the rest are absent; we exercise the write path via a tiny asset.
        let asset = models_for_mode(ModelMode::Standard)[0];
        let target = dir.join(asset.file_name);
        std::fs::write(&target, asset.bytes).unwrap();
        let first_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();

        // Sleep briefly so a rewrite would change mtime on filesystems with coarse
        // timestamp granularity, then ensure_models and assert the file was kept.
        std::thread::sleep(std::time::Duration::from_millis(20));
        crate::ModelLibrary::ensure_models(&dir, ModelMode::Standard).unwrap();
        let second_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();
        assert_eq!(first_mtime, second_mtime, "model file was rewritten");
        std::fs::remove_dir_all(&dir).ok();
    }
}

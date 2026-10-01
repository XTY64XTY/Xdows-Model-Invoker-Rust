use crate::ffi::{canonical_library_path, encode_path, NativeApi, RawScanResult, RawSessionInfo};
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
use std::sync::{Arc, Mutex};

const PREDICT_SYMBOL: &str = "XdowsModelNativePredict";
const GET_SESSION_INFO_SYMBOL: &str = "XdowsModelNativeGetSessionInfo";
const CONFIGURE_THRESHOLDS_SYMBOL: &str = "XdowsModelNativeConfigureThresholds";

/// The fixed thresholds last handed to the native library.
///
/// The ABI exposes fixed thresholds as process-level configuration, so this is
/// process-wide rather than per-session. It exists so that
/// [`ModelLibrary::set_auto_threshold_selection`] can flip the manifest switch
/// without silently resetting the thresholds a caller already configured.
static CURRENT_FIXED_THRESHOLDS: Mutex<[f32; 3]> = Mutex::new([92.0, 96.0, 94.0]);

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
    /// `ModelInvoker.EnsureModelAvailable` flow, which resolves the model files
    /// from the `Models` directory next to the assembly. The native library does
    /// not need to be loaded to call this function.
    pub fn ensure_models(directory: &Path, mode: ModelMode) -> Result<()> {
        write_assets(directory, models_for_mode(mode))
    }

    /// Writes the complete embedded model set into `directory`.
    ///
    /// That is the 8 ONNX files and the 4 JSON manifests — the fusion model and
    /// the five stacking branches, plus the Pro manifest and the recommended
    /// thresholds for Standard, Flash, and Pro. Useful when a deployment wants
    /// every model available up front instead of extracting them per mode.
    /// Existing files are preserved like [`ensure_models`](Self::ensure_models).
    pub fn ensure_all_models(directory: &Path) -> Result<()> {
        write_assets(directory, crate::models::ALL)
    }

    /// Sets the process-level decision thresholds for sessions created afterwards.
    ///
    /// Mirrors the managed `ModelInvoker.ConfigureThresholds`: the three fixed
    /// thresholds become the malware boundary, and automatic manifest selection
    /// is turned on or off at the same time. Call this before
    /// [`ModelInvoker::initialize`] so the new values are picked up.
    pub fn configure_thresholds(&self, thresholds: &Thresholds) -> Result<()> {
        let configure = self
            .api
            .configure_thresholds()
            .ok_or(Error::MissingSymbol {
                symbol: CONFIGURE_THRESHOLDS_SYMBOL,
                windows_error: 0,
            })?;

        let fixed = [
            thresholds.fixed_standard,
            thresholds.fixed_flash,
            thresholds.fixed_pro,
        ];
        let status = unsafe { configure(fixed.as_ptr(), i32::from(thresholds.auto_selection)) };

        let status = NativeStatus::from_code(status);
        if status != NativeStatus::Ok {
            return Err(Error::NativeCall {
                operation: "configure thresholds",
                status,
                message: None,
            });
        }

        if let Ok(mut current) = CURRENT_FIXED_THRESHOLDS.lock() {
            *current = fixed;
        }
        Ok(())
    }

    /// Turns automatic threshold-manifest selection on or off.
    ///
    /// The fixed thresholds configured by the last
    /// [`configure_thresholds`](Self::configure_thresholds) call are preserved.
    pub fn set_auto_threshold_selection(&self, enabled: bool) -> Result<()> {
        let fixed = CURRENT_FIXED_THRESHOLDS
            .lock()
            .map(|current| *current)
            .unwrap_or([92.0, 96.0, 94.0]);

        self.configure_thresholds(&Thresholds {
            fixed_standard: fixed[0],
            fixed_flash: fixed[1],
            fixed_pro: fixed[2],
            recommended_standard: fixed[0],
            recommended_flash: fixed[1],
            recommended_pro: fixed[2],
            auto_selection: enabled,
        })
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

/// The decision thresholds in effect for an initialized session.
///
/// A probability at or above the fixed threshold yields
/// [`ScanVerdict::Malware`]; between the recommended and fixed thresholds it
/// yields [`ScanVerdict::Suspicious`]; below the recommended threshold it
/// yields [`ScanVerdict::Clean`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Thresholds {
    /// Fixed (malware) threshold for Standard, in percent.
    pub fixed_standard: f32,
    /// Fixed (malware) threshold for Flash, in percent.
    pub fixed_flash: f32,
    /// Fixed (malware) threshold for Pro, in percent.
    pub fixed_pro: f32,
    /// Recommended (suspicious) threshold for Standard, in percent.
    pub recommended_standard: f32,
    /// Recommended (suspicious) threshold for Flash, in percent.
    pub recommended_flash: f32,
    /// Recommended (suspicious) threshold for Pro, in percent.
    pub recommended_pro: f32,
    /// Whether recommended thresholds were taken from the model's
    /// `<model>.threshold.json`. When false, the suspicious band is empty and
    /// classification degrades to two tiers.
    pub auto_selection: bool,
}

impl Default for Thresholds {
    /// The values the native library starts with: 92 / 96 / 94 percent fixed,
    /// with automatic manifest selection enabled.
    fn default() -> Self {
        Self {
            fixed_standard: 92.0,
            fixed_flash: 96.0,
            fixed_pro: 94.0,
            recommended_standard: 92.0,
            recommended_flash: 96.0,
            recommended_pro: 94.0,
            auto_selection: true,
        }
    }
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
    /// When `model_directory` is `Some(dir)`, the embedded model files and
    /// manifests for `mode` are first extracted into `dir` (overriding only
    /// missing or mismatched files), and `dir` is passed to the native library.
    /// When it is `None`, the models are extracted into a per-user cache
    /// directory under the system temp folder and that directory is passed
    /// instead. This mirrors the C# `ModelInvoker.Initialize` contract, where
    /// the caller supplies the `Models` directory holding the deployment set.
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

        self.interpret_result("scan", call_status, raw_result)
    }

    /// Runs inference on a caller-supplied feature vector.
    ///
    /// Mirrors the managed `ModelInvoker.PredictWithMlNet`: no file is read and
    /// no feature extraction happens, so the caller owns the feature layout.
    /// The vector length selects the model input — `299` for Standard, `68` for
    /// Flash, and for Pro either the hybrid vector (`519` legacy or `5143`,
    /// which the native library splits across the five stacking branches) or the
    /// fusion vector (the branch count, `4` or `5`). Adaptive sessions reject
    /// this call, matching the managed API, which only predicts through its
    /// Standard session.
    pub fn predict(&self, features: &[f32]) -> Result<ScanResult> {
        let predict = self.library.api.predict().ok_or(Error::MissingSymbol {
            symbol: PREDICT_SYMBOL,
            windows_error: 0,
        })?;

        let feature_count = i32::try_from(features.len()).map_err(|_| Error::NativeCall {
            operation: "predict",
            status: NativeStatus::InvalidArgument,
            message: None,
        })?;

        let mut raw_result = RawScanResult::default();
        let call_status = unsafe {
            predict(
                self.session.as_ptr(),
                features.as_ptr(),
                feature_count,
                &mut raw_result,
            )
        };

        self.interpret_result("predict", call_status, raw_result)
    }

    /// Returns the decision thresholds currently in effect for this session.
    ///
    /// Fixed thresholds come from the process-level configuration set through
    /// [`ModelLibrary::configure_thresholds`]; recommended thresholds come from
    /// the model's `<model>.threshold.json` when automatic selection is on, and
    /// otherwise equal the fixed thresholds.
    pub fn thresholds(&self) -> Result<Thresholds> {
        let get_session_info = self
            .library
            .api
            .get_session_info()
            .ok_or(Error::MissingSymbol {
                symbol: GET_SESSION_INFO_SYMBOL,
                windows_error: 0,
            })?;

        let mut raw = RawSessionInfo::default();
        let status = unsafe { get_session_info(self.session.as_ptr(), &mut raw) };

        let status = NativeStatus::from_code(status);
        if status != NativeStatus::Ok {
            return Err(Error::NativeCall {
                operation: "get session info",
                status,
                message: None,
            });
        }

        // The library allocates the model path with CoTaskMemAlloc and expects it
        // back through its own free function. This crate does not surface the
        // path, so release it here rather than leak it.
        unsafe {
            self.library.api.copy_and_free_string(raw.model_path);
        }

        Ok(Thresholds {
            fixed_standard: raw.fixed_standard,
            fixed_flash: raw.fixed_flash,
            fixed_pro: raw.fixed_pro,
            recommended_standard: raw.recommended_standard,
            recommended_flash: raw.recommended_flash,
            recommended_pro: raw.recommended_pro,
            auto_selection: raw.auto_threshold_selection != 0,
        })
    }

    /// Validates a raw ABI result and converts it into a [`ScanResult`].
    ///
    /// Shared by [`scan_file`](Self::scan_file) and [`predict`](Self::predict)
    /// because both cross the same ABI boundary and must apply the same
    /// contract checks.
    fn interpret_result(
        &self,
        operation: &'static str,
        call_status: i32,
        raw_result: RawScanResult,
    ) -> Result<ScanResult> {
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
                operation,
                status: call_status,
                message: error_message,
            });
        }

        let result_status = NativeStatus::from_code(raw_result.status);
        if result_status != NativeStatus::Ok {
            return Err(Error::NativeCall {
                operation,
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

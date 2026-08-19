use crate::{Error, Result};
use std::ffi::c_void;
use std::path::{Path, PathBuf};

/// The scan result layout from `xdows_model_native.h`.
#[repr(C)]
pub(crate) struct RawScanResult {
    pub size: i32,
    pub status: i32,
    pub is_threat: i32,
    pub probability: f32,
    pub detection_name: *mut u16,
    pub error_message: *mut u16,
    pub verdict: i32,
}

impl Default for RawScanResult {
    fn default() -> Self {
        Self {
            size: std::mem::size_of::<Self>() as i32,
            status: 0,
            is_threat: 0,
            probability: 0.0,
            detection_name: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
            verdict: 0,
        }
    }
}

#[cfg(windows)]
type InitializeFn = unsafe extern "system" fn(*const u16, i32, *mut *mut c_void) -> i32;
#[cfg(windows)]
type ScanFileFn = unsafe extern "system" fn(*mut c_void, *const u16, *mut RawScanResult) -> i32;
#[cfg(windows)]
type ShutdownFn = unsafe extern "system" fn(*mut c_void);
#[cfg(windows)]
type FreeStringFn = unsafe extern "system" fn(*mut u16);

#[cfg(windows)]
type ModuleHandle = *mut c_void;

/// Owns the loaded DLL and resolved function table.
#[cfg(windows)]
pub(crate) struct NativeApi {
    module: ModuleHandle,
    initialize: InitializeFn,
    scan_file: ScanFileFn,
    shutdown: ShutdownFn,
    free_string: FreeStringFn,
}

#[cfg(not(windows))]
pub(crate) struct NativeApi;

#[cfg(windows)]
unsafe impl Send for NativeApi {}
#[cfg(windows)]
unsafe impl Sync for NativeApi {}

impl NativeApi {
    #[cfg(windows)]
    pub(crate) fn load(path: &Path) -> Result<Self> {
        const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
        const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;

        let wide_path = encode_path(path)?;
        let module = unsafe {
            LoadLibraryExW(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            )
        };
        if module.is_null() {
            return Err(Error::LibraryLoad {
                path: path.to_path_buf(),
                windows_error: unsafe { GetLastError() },
            });
        }

        let loaded = (|| {
            let initialize = unsafe {
                std::mem::transmute::<*mut c_void, InitializeFn>(resolve(
                    module,
                    "XdowsModelNativeInitialize",
                    b"XdowsModelNativeInitialize\0",
                )?)
            };
            let scan_file = unsafe {
                std::mem::transmute::<*mut c_void, ScanFileFn>(resolve(
                    module,
                    "XdowsModelNativeScanFile",
                    b"XdowsModelNativeScanFile\0",
                )?)
            };
            let shutdown = unsafe {
                std::mem::transmute::<*mut c_void, ShutdownFn>(resolve(
                    module,
                    "XdowsModelNativeShutdown",
                    b"XdowsModelNativeShutdown\0",
                )?)
            };
            let free_string = unsafe {
                std::mem::transmute::<*mut c_void, FreeStringFn>(resolve(
                    module,
                    "XdowsModelNativeFreeString",
                    b"XdowsModelNativeFreeString\0",
                )?)
            };

            Ok(Self {
                module,
                initialize,
                scan_file,
                shutdown,
                free_string,
            })
        })();

        if loaded.is_err() {
            unsafe {
                FreeLibrary(module);
            }
        }
        loaded
    }

    #[cfg(not(windows))]
    pub(crate) fn load(_path: &Path) -> Result<Self> {
        Err(Error::UnsupportedPlatform)
    }

    #[cfg(windows)]
    /// Calls the loaded initialization export.
    ///
    /// # Safety
    ///
    /// `model_directory` must be null or point to a NUL-terminated UTF-16
    /// string, and `session` must be valid for one pointer write.
    pub(crate) unsafe fn initialize(
        &self,
        model_directory: *const u16,
        mode: i32,
        session: *mut *mut c_void,
    ) -> i32 {
        unsafe { (self.initialize)(model_directory, mode, session) }
    }

    #[cfg(not(windows))]
    /// Non-Windows placeholder for the initialization export.
    ///
    /// # Safety
    ///
    /// This function is unreachable because `NativeApi::load` always fails on
    /// non-Windows platforms.
    pub(crate) unsafe fn initialize(
        &self,
        _model_directory: *const u16,
        _mode: i32,
        _session: *mut *mut c_void,
    ) -> i32 {
        unreachable!("NativeApi cannot be constructed on this platform")
    }

    #[cfg(windows)]
    /// Calls the loaded scan export.
    ///
    /// # Safety
    ///
    /// `session` must be a live session returned by this API, `file_path` must
    /// be a NUL-terminated UTF-16 string, and `result` must be writable.
    pub(crate) unsafe fn scan_file(
        &self,
        session: *mut c_void,
        file_path: *const u16,
        result: *mut RawScanResult,
    ) -> i32 {
        unsafe { (self.scan_file)(session, file_path, result) }
    }

    #[cfg(not(windows))]
    /// Non-Windows placeholder for the scan export.
    ///
    /// # Safety
    ///
    /// This function is unreachable because `NativeApi::load` always fails on
    /// non-Windows platforms.
    pub(crate) unsafe fn scan_file(
        &self,
        _session: *mut c_void,
        _file_path: *const u16,
        _result: *mut RawScanResult,
    ) -> i32 {
        unreachable!("NativeApi cannot be constructed on this platform")
    }

    #[cfg(windows)]
    /// Calls the loaded shutdown export.
    ///
    /// # Safety
    ///
    /// `session` must be a live session returned by this API and must not be
    /// used again after the call.
    pub(crate) unsafe fn shutdown(&self, session: *mut c_void) {
        unsafe { (self.shutdown)(session) }
    }

    #[cfg(not(windows))]
    /// Non-Windows placeholder for the shutdown export.
    ///
    /// # Safety
    ///
    /// This function is unreachable because `NativeApi::load` always fails on
    /// non-Windows platforms.
    pub(crate) unsafe fn shutdown(&self, _session: *mut c_void) {
        unreachable!("NativeApi cannot be constructed on this platform")
    }

    #[cfg(windows)]
    /// Copies a native UTF-16 allocation and releases it through the same DLL.
    ///
    /// # Safety
    ///
    /// `value` must be null or a valid NUL-terminated string allocated by the
    /// loaded Xdows-Model library and not previously freed.
    pub(crate) unsafe fn copy_and_free_string(&self, value: *mut u16) -> Option<String> {
        if value.is_null() {
            return None;
        }

        let mut length = 0usize;
        while unsafe { *value.add(length) } != 0 {
            length += 1;
        }
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) });
        unsafe { (self.free_string)(value) };
        Some(text)
    }

    #[cfg(not(windows))]
    /// Non-Windows placeholder for native string ownership transfer.
    ///
    /// # Safety
    ///
    /// This function is unreachable because `NativeApi::load` always fails on
    /// non-Windows platforms.
    pub(crate) unsafe fn copy_and_free_string(&self, _value: *mut u16) -> Option<String> {
        unreachable!("NativeApi cannot be constructed on this platform")
    }
}

#[cfg(windows)]
impl Drop for NativeApi {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

#[cfg(windows)]
/// Resolves one required export from a loaded module.
///
/// # Safety
///
/// `module` must be a live module handle, and `nul_terminated_symbol` must end
/// in a NUL byte and remain valid for the duration of the call.
unsafe fn resolve(
    module: ModuleHandle,
    symbol: &'static str,
    nul_terminated_symbol: &'static [u8],
) -> Result<*mut c_void> {
    let address = unsafe { GetProcAddress(module, nul_terminated_symbol.as_ptr()) };
    if address.is_null() {
        Err(Error::MissingSymbol {
            symbol,
            windows_error: unsafe { GetLastError() },
        })
    } else {
        Ok(address)
    }
}

#[cfg(windows)]
pub(crate) fn encode_path(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(Error::InvalidPath {
            path: path.to_path_buf(),
            reason: "contains a NUL character",
        });
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(not(windows))]
pub(crate) fn encode_path(_path: &Path) -> Result<Vec<u16>> {
    Err(Error::UnsupportedPlatform)
}

pub(crate) fn canonical_library_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize().map_err(|source| Error::Io {
        operation: "resolve native library",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(windows)]
#[link(name = "kernel32")]
#[allow(non_snake_case)]
extern "system" {
    fn LoadLibraryExW(file_name: *const u16, file: *mut c_void, flags: u32) -> ModuleHandle;
    fn GetProcAddress(module: ModuleHandle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: ModuleHandle) -> i32;
    fn GetLastError() -> u32;
}

#[cfg(test)]
mod tests {
    use super::RawScanResult;

    #[test]
    fn raw_result_has_expected_pointer_alignment() {
        let expected = if cfg!(target_pointer_width = "64") {
            40
        } else {
            28
        };
        assert_eq!(std::mem::size_of::<RawScanResult>(), expected);
    }
}

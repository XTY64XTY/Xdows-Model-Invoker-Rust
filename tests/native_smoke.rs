use std::env;
use std::path::Path;
use xdows_model_invoker::{ModelInvoker, ModelLibrary, ModelMode};

#[test]
#[ignore = "requires XDOWS_NATIVE_DLL, XDOWS_MODEL_DIR, and XDOWS_SAMPLE_FILE"]
fn scans_with_all_model_modes() {
    let dll = env::var_os("XDOWS_NATIVE_DLL").expect("XDOWS_NATIVE_DLL is required");
    let model_directory = env::var_os("XDOWS_MODEL_DIR").expect("XDOWS_MODEL_DIR is required");
    let sample = env::var_os("XDOWS_SAMPLE_FILE").expect("XDOWS_SAMPLE_FILE is required");

    let library = ModelLibrary::load(dll).expect("load native library");
    for mode in [
        ModelMode::Standard,
        ModelMode::Flash,
        ModelMode::Pro,
        ModelMode::Adaptive,
    ] {
        let invoker = ModelInvoker::initialize(&library, mode, Some(Path::new(&model_directory)))
            .unwrap_or_else(|error| panic!("initialize {mode}: {error}"));
        let result = invoker
            .scan_file(Path::new(&sample))
            .unwrap_or_else(|error| panic!("scan with {mode}: {error}"));
        assert!((0.0..=100.0).contains(&result.probability));
    }
}

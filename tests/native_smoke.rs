use std::env;
use std::path::Path;
use xdows_model_invoker::{ModelInvoker, ModelLibrary, ModelMode, NativeStatus, ScanVerdict};

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
        assert!(
            (0.0..=100.0).contains(&result.probability),
            "{mode}: probability {} is out of range",
            result.probability
        );

        // The three-tier verdict and the legacy boolean view must stay in step:
        // a non-Clean verdict is always reported as a threat, and a detection
        // name is never empty when one is produced.
        assert_eq!(
            result.is_threat,
            result.verdict != ScanVerdict::Clean,
            "{mode}: is_threat and verdict disagree"
        );
        if result.verdict != ScanVerdict::Clean {
            assert!(
                result.is_threat,
                "{mode}: a non-Clean verdict must be reported as a threat"
            );
        }
        if let Some(name) = result.detection_name.as_deref() {
            assert!(
                !name.is_empty(),
                "{mode}: an empty detection name was returned"
            );
        }
    }
}

#[test]
#[ignore = "requires XDOWS_NATIVE_DLL and XDOWS_MODEL_DIR"]
fn predicts_feature_vectors_and_reports_thresholds() {
    let dll = env::var_os("XDOWS_NATIVE_DLL").expect("XDOWS_NATIVE_DLL is required");
    let model_directory = env::var_os("XDOWS_MODEL_DIR").expect("XDOWS_MODEL_DIR is required");
    let model_directory = Path::new(&model_directory);

    let library = ModelLibrary::load(dll).expect("load native library");

    // Standard and Flash accept their own feature counts directly.
    for (mode, feature_count) in [(ModelMode::Standard, 299usize), (ModelMode::Flash, 68)] {
        let invoker = ModelInvoker::initialize(&library, mode, Some(model_directory))
            .unwrap_or_else(|error| panic!("initialize {mode}: {error}"));

        let result = invoker
            .predict(&vec![0.0f32; feature_count])
            .unwrap_or_else(|error| panic!("predict with {mode}: {error}"));
        assert!(
            (0.0..=100.0).contains(&result.probability),
            "{mode}: probability {} is out of range",
            result.probability
        );
        // Feature-vector prediction never produces a detection name, matching
        // the managed `PredictWithMlNet`.
        assert!(
            result.detection_name.is_none(),
            "{mode}: prediction produced a detection name"
        );

        let thresholds = invoker
            .thresholds()
            .unwrap_or_else(|error| panic!("thresholds for {mode}: {error}"));
        assert!(
            thresholds.auto_selection,
            "{mode}: manifest selection should default to on"
        );
        assert_eq!(thresholds.fixed_standard, 92.0);
        assert_eq!(thresholds.fixed_flash, 96.0);
        assert_eq!(thresholds.fixed_pro, 94.0);
    }

    let invoker = ModelInvoker::initialize(&library, ModelMode::Standard, Some(model_directory))
        .expect("initialize Standard");

    // A wrong feature count is rejected instead of being silently reshaped.
    let error = invoker
        .predict(&[0.0f32; 10])
        .expect_err("a 10-element vector must be rejected");
    assert_eq!(error.native_status(), Some(NativeStatus::InvalidArgument));

    // Adaptive has no feature-vector entry point, mirroring the managed API.
    let adaptive = ModelInvoker::initialize(&library, ModelMode::Adaptive, Some(model_directory))
        .expect("initialize Adaptive");
    let error = adaptive
        .predict(&[0.0f32; 299])
        .expect_err("Adaptive prediction must be rejected");
    assert_eq!(error.native_status(), Some(NativeStatus::InvalidArgument));

    // A non-PE file is reported as unsupported rather than as a clean verdict,
    // so a scan loop can tell "not a threat" apart from "infrastructure broke".
    let not_pe = env::temp_dir().join("xdows-not-pe-probe.txt");
    std::fs::write(&not_pe, b"not a portable executable").expect("write probe file");
    let error = invoker
        .scan_file(&not_pe)
        .expect_err("a non-PE file must not produce a clean verdict");
    assert!(
        error.is_unsupported_file(),
        "expected an unsupported-file error, got: {error}"
    );
    assert_eq!(error.native_status(), Some(NativeStatus::UnsupportedFile));
    let _ = std::fs::remove_file(&not_pe);
}

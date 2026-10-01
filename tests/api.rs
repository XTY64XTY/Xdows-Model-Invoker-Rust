use xdows_model_invoker::{ModelMode, NativeStatus, ScanVerdict, Thresholds};

#[test]
fn model_modes_match_the_xdows_abi() {
    assert_eq!(ModelMode::Standard.as_raw(), 0);
    assert_eq!(ModelMode::Flash.as_raw(), 1);
    assert_eq!(ModelMode::Pro.as_raw(), 2);
    assert_eq!(ModelMode::Adaptive.as_raw(), 3);
}

#[test]
fn scan_verdicts_match_the_xdows_abi() {
    assert_eq!(ScanVerdict::Clean.as_raw(), 0);
    assert_eq!(ScanVerdict::Suspicious.as_raw(), 1);
    assert_eq!(ScanVerdict::Malware.as_raw(), 2);
    assert_eq!(ScanVerdict::from_raw(0), Some(ScanVerdict::Clean));
    assert_eq!(ScanVerdict::from_raw(1), Some(ScanVerdict::Suspicious));
    assert_eq!(ScanVerdict::from_raw(2), Some(ScanVerdict::Malware));
    assert_eq!(ScanVerdict::from_raw(3), None);
    assert_eq!(ScanVerdict::from_raw(-1), None);
}

#[test]
fn native_status_round_trips_known_and_future_codes() {
    for code in 0..=6 {
        assert_eq!(NativeStatus::from_code(code).code(), code);
    }
    assert_eq!(
        NativeStatus::from_code(6),
        NativeStatus::ModelManifestInvalid
    );
    assert_eq!(NativeStatus::from_code(42), NativeStatus::Unknown(42));
    assert_eq!(NativeStatus::Unknown(42).code(), 42);
}

#[test]
fn default_thresholds_match_the_managed_configuration() {
    let thresholds = Thresholds::default();
    assert_eq!(thresholds.fixed_standard, 92.0);
    assert_eq!(thresholds.fixed_flash, 96.0);
    assert_eq!(thresholds.fixed_pro, 94.0);
    // Recommended values start equal to the fixed ones: the suspicious band is
    // empty until a `<model>.threshold.json` manifest narrows it.
    assert_eq!(thresholds.recommended_standard, 92.0);
    assert_eq!(thresholds.recommended_flash, 96.0);
    assert_eq!(thresholds.recommended_pro, 94.0);
    assert!(thresholds.auto_selection);
}

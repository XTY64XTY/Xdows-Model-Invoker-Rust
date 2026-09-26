//! ONNX model files and deployment manifests embedded into the crate at compile time.
//!
//! The complete Xdows-Model deployment set is embedded with `include_bytes!`,
//! mirroring [`Xdows-Model-Invoker\Models`]. The native library still loads the
//! files from disk, so [`crate::ModelLibrary::ensure_models`] writes the bytes
//! for the selected mode into a directory before initialization.
//!
//! The set is **8 ONNX files and 4 JSON manifests**:
//!
//! * `Xdows-Model.onnx` + `Xdows-Model.threshold.json`
//! * `Xdows-Model-Flash.onnx` + `Xdows-Model-Flash.threshold.json`
//! * `Xdows-Model-Pro.onnx` + `Xdows-Model-Pro.threshold.json` +
//!   `Xdows-Model-Pro.manifest.json`
//! * `Xdows-Model-Pro-{Standard,Flash,RawStat,Structural,ImportBehavior}.onnx`
//!
//! The threshold manifests are not decoration. The native library reads
//! `<model>.threshold.json` to obtain the recommended threshold that marks the
//! lower bound of the three-tier `Suspicious` band, and falls back to the fixed
//! threshold when it is absent — in which case `Suspicious` can never occur.
//! The Pro manifest describes the five-branch feature layout and is validated
//! by the managed invoker, so it is carried here to keep the Pro model set
//! deployable as a unit.
//!
//! [`Xdows-Model-Invoker\Models`]: https://github.com/XTY64XTY/Xdows-Model/tree/main/Xdows-Model-Invoker/Models

use crate::ModelMode;

/// One embedded model file or deployment manifest.
#[derive(Clone, Copy)]
pub struct ModelAsset {
    /// The file name expected by the native library in the model directory.
    pub file_name: &'static str,
    /// The embedded file contents.
    pub bytes: &'static [u8],
}

const STANDARD: ModelAsset = ModelAsset {
    file_name: "Xdows-Model.onnx",
    bytes: include_bytes!("../models/Xdows-Model.onnx"),
};

const STANDARD_THRESHOLD: ModelAsset = ModelAsset {
    file_name: "Xdows-Model.threshold.json",
    bytes: include_bytes!("../models/Xdows-Model.threshold.json"),
};

const FLASH: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Flash.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Flash.onnx"),
};

const FLASH_THRESHOLD: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Flash.threshold.json",
    bytes: include_bytes!("../models/Xdows-Model-Flash.threshold.json"),
};

const PRO_MAIN: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Pro.onnx"),
};

const PRO_THRESHOLD: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro.threshold.json",
    bytes: include_bytes!("../models/Xdows-Model-Pro.threshold.json"),
};

const PRO_MANIFEST: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro.manifest.json",
    bytes: include_bytes!("../models/Xdows-Model-Pro.manifest.json"),
};

const PRO_STANDARD: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro-Standard.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Pro-Standard.onnx"),
};

const PRO_FLASH: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro-Flash.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Pro-Flash.onnx"),
};

const PRO_RAW_STAT: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro-RawStat.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Pro-RawStat.onnx"),
};

const PRO_STRUCTURAL: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro-Structural.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Pro-Structural.onnx"),
};

const PRO_IMPORT_BEHAVIOR: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro-ImportBehavior.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Pro-ImportBehavior.onnx"),
};

/// The complete embedded deployment set, in the order the files are written.
pub static ALL: &[&ModelAsset] = &[
    &STANDARD,
    &STANDARD_THRESHOLD,
    &FLASH,
    &FLASH_THRESHOLD,
    &PRO_MAIN,
    &PRO_MANIFEST,
    &PRO_THRESHOLD,
    &PRO_STANDARD,
    &PRO_FLASH,
    &PRO_RAW_STAT,
    &PRO_STRUCTURAL,
    &PRO_IMPORT_BEHAVIOR,
];

static STANDARD_FULL: &[&ModelAsset] = &[&STANDARD, &STANDARD_THRESHOLD];

static FLASH_FULL: &[&ModelAsset] = &[&FLASH, &FLASH_THRESHOLD];

static PRO_FULL: &[&ModelAsset] = &[
    &PRO_MAIN,
    &PRO_MANIFEST,
    &PRO_THRESHOLD,
    &PRO_STANDARD,
    &PRO_FLASH,
    &PRO_RAW_STAT,
    &PRO_STRUCTURAL,
    &PRO_IMPORT_BEHAVIOR,
];

static ADAPTIVE_FULL: &[&ModelAsset] = ALL;

/// Returns the embedded assets that the native library needs for `mode`.
///
/// The selection mirrors `ResolveModelPath`/`ModelNameForMode` in
/// `xdows_model_native.cpp`: Standard and Flash use a single model, Pro loads
/// the fusion model plus its five stacking branches, and Adaptive pulls in the
/// Standard, Flash, and Pro model sets. Every mode also receives the matching
/// recommended-threshold manifest.
pub fn for_mode(mode: ModelMode) -> &'static [&'static ModelAsset] {
    match mode {
        ModelMode::Standard => STANDARD_FULL,
        ModelMode::Flash => FLASH_FULL,
        ModelMode::Pro => PRO_FULL,
        ModelMode::Adaptive => ADAPTIVE_FULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_by_extension(extension: &str) -> usize {
        ALL.iter()
            .filter(|asset| asset.file_name.ends_with(extension))
            .count()
    }

    #[test]
    fn embedded_assets_are_non_empty() {
        for asset in ALL {
            assert!(!asset.bytes.is_empty(), "{} is empty", asset.file_name);
        }
    }

    #[test]
    fn embedded_set_matches_the_xdows_model_deployment() {
        assert_eq!(ALL.len(), 12, "expected 8 ONNX files and 4 JSON manifests");
        assert_eq!(count_by_extension(".onnx"), 8);
        assert_eq!(count_by_extension(".json"), 4);
    }

    #[test]
    fn for_mode_covers_expected_files() {
        assert_eq!(for_mode(ModelMode::Standard).len(), 2);
        assert_eq!(for_mode(ModelMode::Flash).len(), 2);
        assert_eq!(for_mode(ModelMode::Pro).len(), 8);
        assert_eq!(for_mode(ModelMode::Adaptive).len(), 12);
    }

    #[test]
    fn for_mode_always_includes_required_main_model() {
        let standard = for_mode(ModelMode::Standard);
        assert!(standard.iter().any(|a| a.file_name == "Xdows-Model.onnx"));
        let pro = for_mode(ModelMode::Pro);
        assert!(pro.iter().any(|a| a.file_name == "Xdows-Model-Pro.onnx"));
    }

    #[test]
    fn every_mode_ships_its_recommended_threshold_manifest() {
        let cases = [
            (ModelMode::Standard, "Xdows-Model.threshold.json"),
            (ModelMode::Flash, "Xdows-Model-Flash.threshold.json"),
            (ModelMode::Pro, "Xdows-Model-Pro.threshold.json"),
            (ModelMode::Adaptive, "Xdows-Model.threshold.json"),
        ];
        for (mode, expected) in cases {
            assert!(
                for_mode(mode).iter().any(|a| a.file_name == expected),
                "{mode} is missing {expected}"
            );
        }
    }

    #[test]
    fn pro_asset_set_matches_the_embedded_manifest() {
        let manifest = std::str::from_utf8(PRO_MANIFEST.bytes).expect("manifest is UTF-8");
        assert!(
            manifest.contains("\"FusionInputCount\": 5"),
            "not a five-branch manifest"
        );

        for asset in PRO_FULL {
            if asset.file_name.starts_with("Xdows-Model-Pro-") && asset.file_name.ends_with(".onnx")
            {
                assert!(
                    manifest.contains(asset.file_name),
                    "the Pro manifest does not declare {}",
                    asset.file_name
                );
            }
        }
    }
}

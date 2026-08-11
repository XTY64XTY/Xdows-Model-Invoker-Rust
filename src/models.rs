//! ONNX model assets embedded into the crate at compile time.
//!
//! The seven Xdows-Model ONNX files are embedded with `include_bytes!`,
//! mirroring the `EmbeddedResource` entries in
//! `Xdows-Model/Xdows-Model-Invoker/Xdows-Model-Invoker.csproj`. The native
//! library still loads them from disk, so [`crate::ModelLibrary::ensure_models`]
//! writes the bytes for the selected mode into a directory before initialization.

use crate::ModelMode;

/// One model file baked into the crate.
#[derive(Clone, Copy)]
pub struct ModelAsset {
    /// The file name expected by the native library next to `Xdows-Model-Native.dll`.
    pub file_name: &'static str,
    /// The embedded file contents.
    pub bytes: &'static [u8],
}

const STANDARD: ModelAsset = ModelAsset {
    file_name: "Xdows-Model.onnx",
    bytes: include_bytes!("../models/Xdows-Model.onnx"),
};

const FLASH: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Flash.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Flash.onnx"),
};

const PRO_MAIN: ModelAsset = ModelAsset {
    file_name: "Xdows-Model-Pro.onnx",
    bytes: include_bytes!("../models/Xdows-Model-Pro.onnx"),
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

/// All seven embedded model files, in the order the C# invoker lists them.
pub static ALL: &[&ModelAsset] = &[
    &STANDARD,
    &FLASH,
    &PRO_MAIN,
    &PRO_STANDARD,
    &PRO_FLASH,
    &PRO_RAW_STAT,
    &PRO_STRUCTURAL,
];

static PRO_FULL: &[&ModelAsset] = &[
    &PRO_MAIN,
    &PRO_STANDARD,
    &PRO_FLASH,
    &PRO_RAW_STAT,
    &PRO_STRUCTURAL,
];

static ADAPTIVE_FULL: &[&ModelAsset] = &[
    &STANDARD,
    &FLASH,
    &PRO_MAIN,
    &PRO_STANDARD,
    &PRO_FLASH,
    &PRO_RAW_STAT,
    &PRO_STRUCTURAL,
];

/// Returns the embedded assets that the native library needs for `mode`.
///
/// The selection mirrors `ResolveModelPath`/`ModelNameForMode` in
/// `Xdows-Model-Native.cpp`: Standard and Flash use a single model, Pro loads
/// the fusion model plus the four stacking branches when its feature dimension
/// is 4, and Adaptive pulls in the Standard, Flash, and Pro model sets.
pub fn for_mode(mode: ModelMode) -> &'static [&'static ModelAsset] {
    match mode {
        ModelMode::Standard => &[&STANDARD],
        ModelMode::Flash => &[&FLASH],
        ModelMode::Pro => PRO_FULL,
        ModelMode::Adaptive => ADAPTIVE_FULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_assets_are_non_empty() {
        for asset in ALL {
            assert!(!asset.bytes.is_empty(), "{} is empty", asset.file_name);
        }
    }

    #[test]
    fn for_mode_covers_expected_files() {
        assert_eq!(for_mode(ModelMode::Standard).len(), 1);
        assert_eq!(for_mode(ModelMode::Flash).len(), 1);
        assert_eq!(for_mode(ModelMode::Pro).len(), 5);
        assert_eq!(for_mode(ModelMode::Adaptive).len(), 7);
    }

    #[test]
    fn for_mode_always_includes_required_main_model() {
        let standard = for_mode(ModelMode::Standard);
        assert!(standard.iter().any(|a| a.file_name == "Xdows-Model.onnx"));
        let pro = for_mode(ModelMode::Pro);
        assert!(pro.iter().any(|a| a.file_name == "Xdows-Model-Pro.onnx"));
    }
}

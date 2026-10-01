# Xdows-Model-Invoker-Rust

`xdows-model-invoker` 是 [Xdows-Model](https://github.com/XTY64XTY/Xdows-Model) 的安全 Rust 调用库，支持 `Standard`、`Flash`、`Pro` 和 `Adaptive` 四种模型模式。

接口生命周期参考 `Xdows-Model/Xdows-Model-Invoker` 中的 C# `ModelInvoker`：加载运行库、初始化模型、复用会话扫描多个文件，最后自动释放模型。底层通过 `Xdows-Model-Native.dll` 的稳定 C ABI 调用官方特征提取和 ONNX 推理实现，Rust 代码不复制模型特征算法。

## 内置模型

与 `Xdows-Model-Invoker\Models\` 的部署集完全一致，**8 个 ONNX 模型 + 4 个 JSON 清单**以 `include_bytes!` 编译期内置在本 crate 中：

| 文件 | 用途 |
| --- | --- |
| `Xdows-Model.onnx` | Standard 主模型 |
| `Xdows-Model.threshold.json` | Standard 推荐阈值 |
| `Xdows-Model-Flash.onnx` | Flash 主模型 |
| `Xdows-Model-Flash.threshold.json` | Flash 推荐阈值 |
| `Xdows-Model-Pro.onnx` | Pro 融合模型（5 输入） |
| `Xdows-Model-Pro.threshold.json` | Pro 推荐阈值 |
| `Xdows-Model-Pro.manifest.json` | Pro 特征布局与分支清单 |
| `Xdows-Model-Pro-Standard.onnx` | Pro Standard 分支 |
| `Xdows-Model-Pro-Flash.onnx` | Pro Flash 分支 |
| `Xdows-Model-Pro-RawStat.onnx` | Pro RawStat 分支 |
| `Xdows-Model-Pro-Structural.onnx` | Pro Structural 分支 |
| `Xdows-Model-Pro-ImportBehavior.onnx` | Pro ImportBehavior 分支 |

源文件位于仓库 [`models/`](models) 目录。调用 `ModelInvoker::initialize` 时，所需模型会自动写入目标目录（已存在且大小匹配的文件会保留），因此部署侧只需提供 `Xdows-Model-Native.dll` 及其 ONNX Runtime 依赖，无需单独分发 ONNX 文件。`ModelLibrary::ensure_models` / `ensure_all_models` 也可单独调用以提前落盘。

Pro 模式为**五分支 Stacking 集成**（Standard / Flash / RawStat / Structural / ImportBehavior），混合特征 5143 维，融合模型接受 5 个分支概率。旧的四分支 Pro 模型（519 维、4 输入融合、无清单）仍可通过原生库的兼容路径加载，本 crate 亦保留对应文件集。

### 为什么清单也必须内置

- `<model>.threshold.json` 决定三档判定的下界：原生库读取它得到**推荐阈值**，据此把概率划入 `Suspicious` 区间。若清单缺失，原生库静默回退到固定阈值，`Suspicious` 将永远不会出现——即使 API 仍然暴露该档位。
- `Xdows-Model-Pro.manifest.json` 记录五分支的维度、偏移、文件顺序、特征布局指纹与导入哈希参数。原生库与托管调用器一样，在加载五分支 Pro 模型时会强制校验它，任一项不符即拒绝加载；本 crate 一并内置，以保证 Pro 模型集可整体部署，且与上游部署集逐文件对齐。

> 原生库解析 `<model>.threshold.json` 得到推荐阈值，并严格校验 `Xdows-Model-Pro.manifest.json`：五分支模型缺少清单会以 `NativeStatus::ModelManifestInvalid` 初始化失败，旧版四分支模型（无清单）仍走兼容路径。

## 要求

- Windows x64 或 ARM64
- Rust 1.74 或更高版本
- 从 Xdows-Model 构建的 `Xdows-Model-Native.dll`
- 与原生库架构一致的 ONNX Runtime DLL

运行目录应至少包含：

```text
runtime/
|-- Xdows-Model-Native.dll
|-- onnxruntime.dll
`-- onnxruntime_providers_shared.dll
```

ONNX 模型与清单由本 crate 内置，无需单独放置。

## 使用

```rust
use std::path::Path;
use xdows_model_invoker::{ModelInvoker, ModelLibrary};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let library = ModelLibrary::load_from_directory("runtime")?;
    // 模型自动从内置字节提取到 "runtime"，无需手动准备 ONNX 文件。
    let model = ModelInvoker::pro(&library, Some(Path::new("runtime")))?;

    for file in ["samples/one.exe", "samples/two.exe"] {
        let result = model.scan_file(file)?;
        println!(
            "{file}: verdict={}, threat={}, probability={:.2}%, detection={:?}",
            result.verdict,
            result.is_threat,
            result.probability,
            result.detection_name
        );
    }
    Ok(())
}
```

扫描结果 `ScanResult` 提供三档判定 `verdict`（`Clean` / `Suspicious` / `Malware`，对应 ABI 值 0/1/2，与 C# 与原生库语义一致）：概率达到固定阈值时为 `Malware`，介于推荐阈值与固定阈值之间时为 `Suspicious`，低于推荐阈值时为 `Clean`。`is_threat` 保留为旧语义的兼容视图（`Clean` 之外均为威胁）。

非 PE 文件与空文件不再返回 `Clean`，而是以 `NativeStatus::UnsupportedFile` 报错（对应托管库的 `NotSupportedException`）。可用 [`Error::is_unsupported_file`] 把"不是 PE、不是威胁"与真正的基础设施错误区分开；`Error::native_status` 可拿到原始状态码。

四种便捷初始化方法分别为：

```rust
# use std::path::Path;
# use xdows_model_invoker::{ModelInvoker, ModelLibrary};
# fn example(library: &ModelLibrary, model_dir: &Path) -> xdows_model_invoker::Result<()> {
let standard = ModelInvoker::standard(library, Some(model_dir))?;
let flash = ModelInvoker::flash(library, Some(model_dir))?;
let pro = ModelInvoker::pro(library, Some(model_dir))?;
let adaptive = ModelInvoker::adaptive(library, Some(model_dir))?;
# drop((standard, flash, pro, adaptive));
# Ok(())
# }
```

也可以在运行时选择模式：

```rust
# use std::path::Path;
# use xdows_model_invoker::{ModelInvoker, ModelLibrary, ModelMode};
# fn example(library: &ModelLibrary, model_dir: &Path) -> xdows_model_invoker::Result<()> {
let mode = ModelMode::Adaptive;
let model = ModelInvoker::initialize(library, mode, Some(model_dir))?;
# drop(model);
# Ok(())
# }
```

`model_directory` 传 `None` 时，模型与清单会提取到 `%TEMP%\xdows-model-invoker` 并在该目录初始化，便于无需指定输出目录的快速调用：

```rust
# use std::path::Path;
# use xdows_model_invoker::{ModelInvoker, ModelLibrary, ModelMode};
# fn example(library: &ModelLibrary) -> xdows_model_invoker::Result<()> {
let model = ModelInvoker::initialize(library, ModelMode::Adaptive, None)?;
# drop(model);
# Ok(())
# }
```

命令行示例：

```powershell
cargo run --example scan -- `
  .\runtime\Xdows-Model-Native.dll `
  .\runtime `
  adaptive `
  C:\Samples\sample.exe
```

## 阈值

`ModelInvoker::thresholds` 返回该会话生效的阈值（`Thresholds`）：固定阈值默认 Standard 92 / Flash 96 / Pro 94，推荐阈值在自动选择开启时来自模型旁的 `<model>.threshold.json`，否则等于固定阈值。

`ModelLibrary::configure_thresholds` 设置**进程级**固定阈值并同时开关自动选择，与托管 `ModelInvoker.ConfigureThresholds` 一致，需在 `initialize` 之前调用；`ModelLibrary::set_auto_threshold_selection` 只切换自动选择，保留上一次配置的固定阈值。

## 特征向量直接推理

`ModelInvoker::predict(&[f32])` 直接对调用方给定的特征向量推理，对应托管 `ModelInvoker.PredictWithMlNet`，不读文件也不做特征提取：Standard 需 299 维、Flash 需 68 维，Pro 可传混合特征（519/5143，原生内部按五分支切分后融合）或融合向量（分支数 4/5）。Adaptive 会话不支持该调用；与托管 API 一致，预测不产出检测名。

## 错误与线程

所有加载、初始化和扫描错误都通过 `Result` 返回。原生错误字符串会先复制到 Rust `String`，再由原生库自己的释放函数回收，避免跨运行库释放内存。

`ModelLibrary` 可以克隆并在线程间共享。`ModelInvoker` 可以移动到其他线程，但同一会话不能被多个线程同时扫描；并行扫描时应为每个工作线程初始化独立会话。

## 验证

常规检查不需要原生运行库：

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

单元测试会校验内置部署集的完整性：共 12 个资产（8 个 ONNX + 4 个清单）、每个模式各自携带所需的推荐阈值清单，并断言 Pro 清单声明的分支文件名与内置的分支模型逐一对得上。

准备好原生运行库与 PE 样本后，可运行四模式真实冒烟测试（模型已内置，无需设置模型目录）：

```powershell
$env:XDOWS_NATIVE_DLL = "D:\runtime\Xdows-Model-Native.dll"
$env:XDOWS_MODEL_DIR = "D:\runtime"
$env:XDOWS_SAMPLE_FILE = "D:\samples\sample.exe"
cargo test --test native_smoke -- --ignored --nocapture
```

## 许可证

[MIT](LICENSE.txt), Copyright (c) 2026 XTY64XTY.

# Xdows-Model-Invoker-Rust

`xdows-model-invoker` 是 [Xdows-Model](https://github.com/XTY64XTY/Xdows-Model) 的安全 Rust 调用库，支持 `Standard`、`Flash`、`Pro` 和 `Adaptive` 四种模型模式。

接口生命周期参考 `Xdows-Model/Xdows-Model-Invoker` 中的 C# `ModelInvoker`：加载运行库、初始化模型、复用会话扫描多个文件，最后自动释放模型。底层通过 `Xdows-Model-Native.dll` 的稳定 C ABI 调用官方特征提取和 ONNX 推理实现，Rust 代码不复制模型特征算法。

## 内置模型

与 C# 调用器一致，七个 ONNX 模型以 `include_bytes!` 编译期内置在本 crate 中，镜像 `Xdows-Model-Invoker.csproj` 的 `EmbeddedResource` 条目：

- `Xdows-Model.onnx`
- `Xdows-Model-Flash.onnx`
- `Xdows-Model-Pro.onnx`
- `Xdows-Model-Pro-Standard.onnx`
- `Xdows-Model-Pro-Flash.onnx`
- `Xdows-Model-Pro-RawStat.onnx`
- `Xdows-Model-Pro-Structural.onnx`

源文件位于仓库 [`models/`](models) 目录。调用 `ModelInvoker::initialize` 时，所需模型会自动写入目标目录（已存在且大小匹配的文件会保留），因此部署侧只需提供 `Xdows-Model-Native.dll` 及其 ONNX Runtime 依赖，无需单独分发 ONNX 文件。`ModelLibrary::ensure_models` / `ensure_all_models` 也可单独调用以提前落盘。

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

ONNX 模型由本 crate 内置，无需单独放置。

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

`model_directory` 传 `None` 时，模型会提取到 `%TEMP%\xdows-model-invoker` 并在该目录初始化，便于无需指定输出目录的快速调用：

```rust
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

准备好原生运行库与 PE 样本后，可运行四模式真实冒烟测试（模型已内置，无需设置模型目录）：

```powershell
$env:XDOWS_NATIVE_DLL = "D:\runtime\Xdows-Model-Native.dll"
$env:XDOWS_MODEL_DIR = "D:\runtime"
$env:XDOWS_SAMPLE_FILE = "D:\samples\sample.exe"
cargo test --test native_smoke -- --ignored --nocapture
```

## 许可证

[MIT](LICENSE.txt), Copyright (c) 2026 XTY64XTY.


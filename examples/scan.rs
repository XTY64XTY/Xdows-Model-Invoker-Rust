use std::env;
use std::error::Error;
use std::path::Path;
use xdows_model_invoker::{ModelInvoker, ModelLibrary, ModelMode};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 5 {
        eprintln!(
            "Usage: {} <native-dll> <model-directory> <standard|flash|pro|adaptive> <file>",
            arguments.first().map_or("scan", String::as_str)
        );
        std::process::exit(2);
    }

    let mode = parse_mode(&arguments[3])?;
    let library = ModelLibrary::load(&arguments[1])?;
    let invoker = ModelInvoker::initialize(&library, mode, Some(Path::new(&arguments[2])))?;
    let result = invoker.scan_file(&arguments[4])?;

    println!("mode: {}", invoker.mode());
    println!("verdict: {}", result.verdict);
    println!("threat: {}", result.is_threat);
    println!("probability: {:.2}%", result.probability);
    if let Some(name) = result.detection_name {
        println!("detection: {name}");
    }
    Ok(())
}

fn parse_mode(value: &str) -> Result<ModelMode, std::io::Error> {
    match value.to_ascii_lowercase().as_str() {
        "standard" => Ok(ModelMode::Standard),
        "flash" => Ok(ModelMode::Flash),
        "pro" => Ok(ModelMode::Pro),
        "adaptive" => Ok(ModelMode::Adaptive),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mode must be standard, flash, pro, or adaptive",
        )),
    }
}

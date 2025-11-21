//! CLI output helpers with colored terminal support

use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

/// Print success message (green checkmark)
pub fn success(message: &str) {
    let stdout = StandardStream::stdout(ColorChoice::Auto);
    let mut locked = stdout.lock();
    
    // Attempt colored output, fallback to plain if any step fails
    if locked.set_color(ColorSpec::new().set_fg(Some(Color::Green))).is_err()
        || writeln!(&mut locked, "✓ {message}").is_err()
        || locked.reset().is_err()
    {
        // Fallback to plain stdout if colored output fails
        println!("✓ {message}");
    }
    
    log::info!("{message}");
}

/// Print error message (red X)
pub fn error(message: &str) {
    let stderr = StandardStream::stderr(ColorChoice::Auto);
    let mut locked = stderr.lock();
    
    // Attempt colored output, fallback to plain if any step fails
    if locked.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true)).is_err()
        || writeln!(&mut locked, "✗ {message}").is_err()
        || locked.reset().is_err()
    {
        // Fallback to plain stderr if colored output fails
        eprintln!("✗ {message}");
    }
    
    log::error!("{message}");
}

/// Print warning message (yellow)
pub fn warning(message: &str) {
    let stderr = StandardStream::stderr(ColorChoice::Auto);
    let mut locked = stderr.lock();
    
    // Attempt colored output, fallback to plain if any step fails
    if locked.set_color(ColorSpec::new().set_fg(Some(Color::Yellow))).is_err()
        || writeln!(&mut locked, "⚠ {message}").is_err()
        || locked.reset().is_err()
    {
        // Fallback to plain stderr if colored output fails
        eprintln!("⚠ {message}");
    }
    
    log::warn!("{message}");
}

/// Print info message (cyan)
pub fn info(message: &str) {
    let stdout = StandardStream::stdout(ColorChoice::Auto);
    let mut locked = stdout.lock();
    
    // Attempt colored output, fallback to plain if any step fails
    if locked.set_color(ColorSpec::new().set_fg(Some(Color::Cyan))).is_err()
        || writeln!(&mut locked, "ℹ {message}").is_err()
        || locked.reset().is_err()
    {
        // Fallback to plain stdout if colored output fails
        println!("ℹ {message}");
    }
    
    log::info!("{message}");
}

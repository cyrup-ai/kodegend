//! Installation wizard display components for CLI progress

/// Display welcome banner for CLI installation
pub fn show_welcome_banner() {
    use std::io::Write;
    use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    // Top border with cyan color
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        stdout,
        "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    );
    let _ = stdout.reset();

    // Brand name in cyan, centered
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true));
    let _ = writeln!(stdout, "\n                    K O D E G E N . ᴀ ɪ");
    let _ = stdout.reset();

    // Tagline in white
    let _ = writeln!(stdout, "\n              Ultimate MCP Auto-Coding Toolset");

    // Bottom border
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        stdout,
        "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    );
    let _ = stdout.reset();

    let _ = writeln!(stdout, "Installing system daemon service...\n");
    let _ = writeln!(stdout, "This will install:");
    let _ = writeln!(stdout, "  • Kodegen MCP Server daemon");
    let _ = writeln!(stdout, "  • TLS certificate for mcp.kodegen.ai");
    let _ = writeln!(stdout, "  • System service configuration");
    let _ = writeln!(stdout, "  • Chromium browser (~100MB for web scraping)\n");

    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        stdout,
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    );
    let _ = stdout.reset();
}

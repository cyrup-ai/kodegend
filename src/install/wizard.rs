//! Installation wizard display components for CLI progress

use std::path::PathBuf;

/// Results from actual installation (what was really installed)
#[derive(Debug, Clone)]
pub struct InstallationResult {
    pub data_dir: PathBuf,
    pub service_path: PathBuf,
    pub service_started: bool,
    pub certificates_installed: bool,
    pub host_entries_added: bool,
    pub fluent_voice_installed: bool,
    pub certificate_content: Option<String>,
}

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

/// Display installation completion summary
pub fn show_completion(result: &InstallationResult) {
    use std::io::Write;
    use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    // Top border
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        stdout,
        "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    );
    let _ = stdout.reset();

    // Success header in green
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true));
    let _ = writeln!(stdout, "\n                    ✓ INSTALLATION COMPLETE\n");
    let _ = stdout.reset();

    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        stdout,
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    );
    let _ = stdout.reset();

    let _ = writeln!(stdout, "Installed components:");

    // Show components with status indicators
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
    let _ = writeln!(stdout, "  ✓ Kodegen daemon service");
    let _ = stdout.reset();

    if result.certificates_installed {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "  ✓ TLS certificate (mcp.kodegen.ai)");
        let _ = stdout.reset();
    } else {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
        let _ = writeln!(stdout, "  ⚠ TLS certificate (installation failed)");
        let _ = stdout.reset();
    }

    if result.host_entries_added {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "  ✓ Host file entries");
        let _ = stdout.reset();
    } else {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
        let _ = writeln!(stdout, "  ⚠ Host file entries (skipped)");
        let _ = stdout.reset();
    }

    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
    let _ = writeln!(stdout, "  ✓ System service configuration");
    let _ = stdout.reset();

    if result.fluent_voice_installed {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "  ✓ Fluent-voice components");
        let _ = stdout.reset();
    } else {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
        let _ = writeln!(stdout, "  ⚠ Fluent-voice components (optional)");
        let _ = stdout.reset();
    }

    // Service status
    let _ = writeln!(stdout, "\nService status:");
    if result.service_started {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "  ✓ Running at {}", result.service_path.display());
        let _ = stdout.reset();
    } else {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
        let _ = writeln!(stdout, "  ⚠ Installed but not started");
        let _ = stdout.reset();
    }

    // Installation location
    let _ = writeln!(stdout, "\nInstallation location:");
    let _ = writeln!(stdout, "  {}", result.data_dir.display());

    // Bottom border
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        stdout,
        "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    );
    let _ = stdout.reset();

    // Next steps
    let _ = writeln!(
        stdout,
        "\nNext: Restart your MCP client (Claude Desktop, Cursor, Windsurf)"
    );

    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        stdout,
        "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    );
    let _ = stdout.reset();
}

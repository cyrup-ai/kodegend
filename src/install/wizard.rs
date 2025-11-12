//! Interactive installation wizard for `kodegen_install`

use anyhow::Result;
use inquire::Confirm;
use std::path::PathBuf;

/// Installation options gathered from interactive wizard
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub dry_run: bool,
    pub auto_start: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            auto_start: true,
        }
    }
}

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

/// Display welcome banner
fn show_welcome() {
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
pub fn show_completion(_options: &InstallOptions, result: &InstallationResult) {
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

/// Run interactive installation wizard
pub fn run_wizard() -> Result<InstallOptions> {
    show_welcome();

    // Prompt 1: Dry-run mode
    let dry_run = Confirm::new("Perform dry-run (preview changes without installing)?")
        .with_default(false)
        .with_help_message("Dry-run shows what would be installed without making changes")
        .prompt()
        .map_err(|e| anyhow::anyhow!("Prompt cancelled: {}", e))?;

    // Prompt 2: Auto-start service
    let auto_start = Confirm::new("Start service automatically after installation?")
        .with_default(true)
        .with_help_message("The daemon will start on system boot (systemd/launchd)")
        .prompt()
        .map_err(|e| anyhow::anyhow!("Prompt cancelled: {}", e))?;

    // Show summary of selections
    println!("\n📋 Installation Summary:");
    println!("  • Dry-run mode: {}", if dry_run { "Yes (preview only)" } else { "No (will install)" });
    println!("  • Auto-start: {}", if auto_start { "Yes (on boot)" } else { "No (manual start)" });
    println!();

    // Final confirmation before proceeding
    let proceed = Confirm::new("Proceed with these settings?")
        .with_default(true)
        .prompt()
        .map_err(|e| anyhow::anyhow!("Prompt cancelled: {}", e))?;

    if !proceed {
        return Err(anyhow::anyhow!("Installation cancelled by user"));
    }

    Ok(InstallOptions {
        dry_run,
        auto_start,
    })
}

/// Check if running in non-interactive mode (CLI flags provided)
///
/// Returns true if the installer should skip the interactive wizard and run
/// in automated CLI mode.
///
/// Non-interactive mode is triggered by:
/// 1. Explicit `--no-interaction` flag (highest priority)
/// 2. Automation-specific flags (`--dry-run` or `--uninstall`)
///
/// Priority reasoning:
/// - `--no-interaction` always wins (explicit non-interactive command)
/// - `--dry-run` and `--uninstall` are automation-focused operations
pub fn is_non_interactive(cli: &super::cli::Cli) -> bool {
    // Priority 1: Explicit non-interactive flag always takes precedence
    if cli.no_interaction {
        return true;
    }

    // Priority 2: Automation-specific flags only
    // REMOVED: cli.no_start (affects WHAT, not HOW)
    // REMOVED: cli.binary check (affects WHAT to install, not HOW to install)
    cli.dry_run || cli.uninstall
}

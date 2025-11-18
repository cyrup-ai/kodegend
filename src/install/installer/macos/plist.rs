//! launchd plist file generation for macOS daemon services.

use std::collections::HashMap;

use plist::Value;

use super::{InstallerBuilder, InstallerError};

/// Generate a launchd plist configuration file for the daemon
pub(super) fn generate_plist(b: &InstallerBuilder) -> Result<String, InstallerError> {
    let mut plist = HashMap::new();

    // Basic properties
    plist.insert("Label".to_string(), Value::String(b.label.clone()));
    plist.insert("Disabled".to_string(), Value::Boolean(false));

    // Program and arguments
    let mut program_args = vec![Value::String(format!("/usr/local/bin/{}", b.label))];
    program_args.extend(b.args.iter().map(|a| Value::String(a.clone())));
    plist.insert("ProgramArguments".to_string(), Value::Array(program_args));

    // Environment variables
    if !b.env.is_empty() {
        let env_dict: HashMap<String, Value> = b
            .env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        plist.insert(
            "EnvironmentVariables".to_string(),
            Value::Dictionary(env_dict.into_iter().collect()),
        );
    }

    // User/Group
    plist.insert("UserName".to_string(), Value::String(b.run_as_user.clone()));
    if b.run_as_group != "wheel" && b.run_as_group != "staff" {
        plist.insert(
            "GroupName".to_string(),
            Value::String(b.run_as_group.clone()),
        );
    }

    // Auto-restart
    plist.insert(
        "KeepAlive".to_string(),
        if b.auto_restart {
            Value::Dictionary(
                vec![("SuccessfulExit".to_string(), Value::Boolean(false))]
                    .into_iter()
                    .collect(),
            )
        } else {
            Value::Boolean(false)
        },
    );

    // Logging
    plist.insert(
        "StandardOutPath".to_string(),
        Value::String(format!("/var/log/{}/stdout.log", b.label)),
    );
    plist.insert(
        "StandardErrorPath".to_string(),
        Value::String(format!("/var/log/{}/stderr.log", b.label)),
    );

    // Run at load
    plist.insert("RunAtLoad".to_string(), Value::Boolean(true));

    // Network dependency
    if b.wants_network {
        plist.insert(
            "LimitLoadToSessionType".to_string(),
            Value::String("System".to_string()),
        );
    }

    // Generate XML
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(plist.into_iter().collect()))
        .map_err(|e| InstallerError::System(format!("Failed to generate plist: {e}")))?;

    String::from_utf8(buf)
        .map_err(|e| InstallerError::System(format!("Plist contains invalid UTF-8: {e}")))
}

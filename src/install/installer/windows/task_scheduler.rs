//! Windows Task Scheduler support for per-user daemon execution.
//!
//! Task Scheduler allows running programs at user logon without admin privileges,
//! making it ideal for user-scope installations.

use super::{InstallerBuilder, InstallerError};
use std::process::Command;

/// Map Unix nice value (-20 to 19) to Windows Task Scheduler priority (0-10)
///
/// Windows Task Scheduler Priority Scale:
/// - 0 = Realtime (highest)
/// - 1 = High
/// - 2-3 = Above Normal
/// - 4-6 = Normal
/// - 7-8 = Below Normal
/// - 9-10 = Idle (lowest)
///
/// Unix nice Scale:
/// - -20 = Highest priority
/// - 0 = Normal priority
/// - 19 = Lowest priority
///
/// Mapping Strategy:
/// - nice -20..-15 → priority 1 (High)
/// - nice -14..-5  → priority 4 (Normal, upper range)
/// - nice -4..4    → priority 5 (Normal, middle)
/// - nice 5..14    → priority 7 (Below Normal)
/// - nice 15..19   → priority 9 (Idle)
fn nice_to_task_scheduler_priority(nice: i32) -> u8 {
    match nice {
        i32::MIN..=-15 => 1,  // High priority
        -14..=-5       => 4,  // Normal (upper)
        -4..=4         => 5,  // Normal (middle)
        5..=14         => 7,  // Below Normal
        15..=i32::MAX  => 9,  // Idle
    }
}

/// Create a scheduled task that runs at user logon
pub(super) fn create_user_scheduled_task(builder: &InstallerBuilder) -> Result<(), InstallerError> {
    // Generate Task Scheduler XML
    let task_xml = generate_task_xml(builder)?;
    
    // Write XML to temp file
    let temp_dir = std::env::temp_dir();
    let xml_path = temp_dir.join(format!("kodegen_task_{}.xml", uuid::Uuid::new_v4()));
    std::fs::write(&xml_path, task_xml)
        .map_err(|e| InstallerError::System(format!("Failed to write task XML: {}", e)))?;
    
    // Create task using schtasks.exe (no elevation required for current user tasks)
    let output = Command::new("schtasks.exe")
        .args([
            "/create",
            "/tn", &builder.label,              // Task name
            "/xml", &xml_path.to_string_lossy(), // XML definition
            "/f",                                 // Force (overwrite if exists)
        ])
        .output()
        .map_err(|e| InstallerError::System(format!("Failed to execute schtasks.exe: {}", e)))?;
    
    // Clean up temp file
    let _ = std::fs::remove_file(&xml_path);
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InstallerError::System(format!(
            "Failed to create scheduled task: {}",
            stderr
        )));
    }
    
    log::info!("Created scheduled task: {}", builder.label);
    Ok(())
}

/// Generate Task Scheduler XML for logon trigger
fn generate_task_xml(builder: &InstallerBuilder) -> Result<String, InstallerError> {
    // Get current username for LogonTrigger
    let username = std::env::var("USERNAME")
        .map_err(|_| InstallerError::System("Failed to get USERNAME".to_string()))?;
    
    let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| ".".to_string());
    let user_id = format!(r"{}\{}", domain, username);
    
    // Build command with arguments
    let command = builder.program.display().to_string();
    let arguments = builder.args.join(" ");
    
    // Get resource limits from builder or use defaults
    let limits = builder.resource_limits.as_ref().cloned().unwrap_or_default();
    let priority = nice_to_task_scheduler_priority(limits.nice);
    
    // Generate XML using Microsoft Task Scheduler Schema
    // Reference: https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
    <URI>\{label}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_id}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_id}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>{priority}</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>"#,
        description = xml_escape(&builder.description),
        label = xml_escape(&builder.label),
        user_id = xml_escape(&user_id),
        command = xml_escape(&command),
        arguments = xml_escape(&arguments),
        priority = priority,
    );
    
    Ok(xml)
}

/// Escape XML special characters
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Start a scheduled task (run it immediately)
pub(super) fn start_user_scheduled_task(task_name: &str) -> Result<(), InstallerError> {
    let output = Command::new("schtasks.exe")
        .args(["/run", "/tn", task_name])
        .output()
        .map_err(|e| InstallerError::System(format!("Failed to execute schtasks.exe: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InstallerError::System(format!(
            "Failed to start scheduled task: {}",
            stderr
        )));
    }
    
    Ok(())
}

/// Delete a scheduled task
pub(super) fn delete_user_scheduled_task(task_name: &str) -> Result<(), InstallerError> {
    let output = Command::new("schtasks.exe")
        .args(["/delete", "/tn", task_name, "/f"])
        .output()
        .map_err(|e| InstallerError::System(format!("Failed to execute schtasks.exe: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't treat "not found" as an error
        if !stderr.contains("cannot find") {
            return Err(InstallerError::System(format!(
                "Failed to delete scheduled task: {}",
                stderr
            )));
        }
    }
    
    Ok(())
}

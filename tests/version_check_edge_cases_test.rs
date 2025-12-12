//! Edge case testing for version check logic
//!
//! Tests scenarios that might cause unexpected behavior:
//! - When crates.io API fails
//! - When binary is not found
//! - When version parsing fails

use kodegend::install::detection::{self, ComponentStatus};

#[tokio::test]
async fn test_what_happens_when_cratesio_unavailable() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== CRATES.IO UNAVAILABLE SCENARIO ===\n");

    // Try to get version from a non-existent crate (simulates API failure)
    let bad_version = detection::get_crates_io_version("nonexistent-crate-xyz-12345").await;
    println!("Fetching non-existent crate: {:?}", bad_version);

    // This should return None
    assert_eq!(bad_version, None, "Non-existent crate should return None");

    println!("\nNow let's see what happens when we check kodegen but crates.io fails...");
    
    // The code at line 502-505 in detection.rs says:
    // (Some(_), None) => ComponentStatus::Ok  // Conservative fallback
    //
    // This means: if installed version exists but crates.io check fails,
    // it assumes everything is OK and returns ComponentStatus::Ok
    //
    // This would PREVENT downloads, not cause them!

    println!("\n=== TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_when_binary_not_found() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== BINARY NOT FOUND SCENARIO ===\n");

    // Check a binary that doesn't exist
    let not_found = detection::get_installed_binary_version("nonexistent-binary-xyz").await;
    println!("Non-existent binary version: {:?}", not_found);
    
    assert_eq!(not_found, None, "Non-existent binary should return None");

    println!("\nAccording to check_kodegen_version_status() logic:");
    println!("  (None, _) => ComponentStatus::Missing");
    println!("  This would trigger a download (correct behavior)");

    println!("\n=== TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_version_parsing_with_metadata() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== VERSION STRING PARSING TEST ===\n");

    // Test semver parsing with different formats
    use semver::Version;

    let test_cases = vec![
        ("0.10.5", "0.10.5", true),
        ("0.10.5", "0.10.6", false),
        ("0.10.6", "0.10.5", true),
        ("0.10.5-beta", "0.10.5", false),
        ("0.10.5", "0.10.5-beta", true),
        ("0.10.5+metadata", "0.10.5", true),  // metadata is ignored in semver
        ("0.10.5", "0.10.5+metadata", true),  // metadata is ignored
    ];

    for (installed_str, latest_str, expected_ok) in test_cases {
        match (Version::parse(installed_str), Version::parse(latest_str)) {
            (Ok(installed), Ok(latest)) => {
                let is_ok = installed >= latest;
                let status_str = if is_ok { "Ok" } else { "NeedsUpdate" };
                
                println!(
                    "{:20} vs {:20} => {} (installed >= latest: {})",
                    installed_str, latest_str, status_str, is_ok
                );

                assert_eq!(
                    is_ok, expected_ok,
                    "Unexpected result for {} vs {}",
                    installed_str, latest_str
                );
            }
            _ => {
                println!("{:20} vs {:20} => CheckFailed (parse error)", installed_str, latest_str);
            }
        }
    }

    println!("\n=== TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_actual_kodegen_version_output_parsing() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== ACTUAL KODEGEN --version OUTPUT ===\n");

    // Run the actual command and see what it returns
    use tokio::process::Command;
    
    let output = Command::new("kodegen")
        .arg("--version")
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            println!("Raw output:");
            println!("{}", stdout);
            
            // Test the regex parsing
            let re = regex::Regex::new(r"\b(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)\b").unwrap();
            
            if let Some(cap) = re.captures(&stdout) {
                if let Some(m) = cap.get(1) {
                    println!("\nExtracted version: {}", m.as_str());
                }
            } else {
                println!("\n⚠ WARNING: Regex failed to extract version!");
            }
        }
        Ok(out) => {
            println!("Command failed with status: {}", out.status);
            println!("stderr: {}", String::from_utf8_lossy(&out.stderr));
        }
        Err(e) => {
            println!("Failed to execute kodegen: {}", e);
        }
    }

    println!("\n=== TEST COMPLETE ===\n");
}

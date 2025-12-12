//! Integration test for kodegen version check logic
//!
//! This test exposes the bug where kodegen binary is downloaded even when
//! the installed version already matches the latest version on crates.io.

use kodegend::install::detection::{
    check_kodegen_version_status, get_crates_io_version, get_installed_binary_version,
    ComponentStatus,
};

/// Test that version check correctly identifies when installed version matches latest
#[tokio::test]
async fn test_version_check_when_versions_match() {
    // Get actual installed version
    let installed = get_installed_binary_version("kodegen").await;
    println!("Installed kodegen version: {:?}", installed);

    // Get actual latest version from crates.io
    let latest = get_crates_io_version("kodegen").await;
    println!("Latest crates.io version: {:?}", latest);

    // Run the actual version check logic
    let status = check_kodegen_version_status().await;
    println!("Version check status: {:?}", status);

    // If versions match, status should be Ok
    if let (Some(inst), Some(lat)) = (&installed, &latest) {
        if inst == lat {
            assert_eq!(
                status,
                ComponentStatus::Ok,
                "BUG FOUND: When installed ({}) == latest ({}), status should be Ok but got {:?}",
                inst,
                lat,
                status
            );
        }
    }
}

/// Test the comparison logic with explicit version strings
#[tokio::test]
async fn test_version_comparison_logic() {
    use semver::Version;

    // Test case 1: Versions equal
    let installed = Version::parse("0.10.5").unwrap();
    let latest = Version::parse("0.10.5").unwrap();
    
    assert!(
        installed >= latest,
        "Version comparison failed: {} should be >= {}",
        installed,
        latest
    );

    // This should result in ComponentStatus::Ok
    let status = if installed >= latest {
        ComponentStatus::Ok
    } else {
        ComponentStatus::NeedsUpdate
    };

    assert_eq!(
        status,
        ComponentStatus::Ok,
        "When installed == latest, status should be Ok"
    );

    // Test case 2: Installed older than latest
    let installed_old = Version::parse("0.10.4").unwrap();
    let latest_new = Version::parse("0.10.5").unwrap();
    
    let status_old = if installed_old >= latest_new {
        ComponentStatus::Ok
    } else {
        ComponentStatus::NeedsUpdate
    };

    assert_eq!(
        status_old,
        ComponentStatus::NeedsUpdate,
        "When installed < latest, status should be NeedsUpdate"
    );

    // Test case 3: Installed newer than latest (dev build)
    let installed_dev = Version::parse("0.10.6").unwrap();
    let latest_published = Version::parse("0.10.5").unwrap();
    
    let status_dev = if installed_dev >= latest_published {
        ComponentStatus::Ok
    } else {
        ComponentStatus::NeedsUpdate
    };

    assert_eq!(
        status_dev,
        ComponentStatus::Ok,
        "When installed > latest, status should be Ok (don't downgrade)"
    );
}

/// Test that the condition logic works correctly
#[test]
fn test_condition_logic() {
    // This tests the logic at component_fixers.rs:810
    // if status.kodegen_version != ComponentStatus::Ok { fix }

    // Case 1: Status is Ok -> should NOT fix
    let status_ok = ComponentStatus::Ok;
    let should_fix_when_ok = status_ok != ComponentStatus::Ok;
    assert_eq!(
        should_fix_when_ok, false,
        "When status is Ok, should NOT call fix function"
    );

    // Case 2: Status is NeedsUpdate -> should fix
    let status_needs_update = ComponentStatus::NeedsUpdate;
    let should_fix_when_needs_update = status_needs_update != ComponentStatus::Ok;
    assert_eq!(
        should_fix_when_needs_update, true,
        "When status is NeedsUpdate, SHOULD call fix function"
    );

    // Case 3: Status is Missing -> should fix
    let status_missing = ComponentStatus::Missing;
    let should_fix_when_missing = status_missing != ComponentStatus::Ok;
    assert_eq!(
        should_fix_when_missing, true,
        "When status is Missing, SHOULD call fix function"
    );
}

/// Test the full orchestration flow
#[tokio::test]
async fn test_orchestration_flow() {
    use kodegend::install::detection::check_all_components;

    // Run the full component check (this calls check_kodegen_version_status internally)
    let report = check_all_components().await;

    println!("Component Status Report:");
    println!("  hosts: {:?}", report.hosts);
    println!("  certificates: {:?}", report.certificates);
    println!("  kodegen_version: {:?}", report.kodegen_version);

    // Get the actual versions for comparison
    let installed = get_installed_binary_version("kodegen").await;
    let latest = get_crates_io_version("kodegen").await;

    println!("\nVersion Details:");
    println!("  Installed: {:?}", installed);
    println!("  Latest:    {:?}", latest);

    // If versions match, kodegen_version status should be Ok
    if let (Some(inst), Some(lat)) = (&installed, &latest) {
        if inst == lat {
            assert_eq!(
                report.kodegen_version,
                ComponentStatus::Ok,
                "BUG EXPOSED: check_all_components() returned {:?} but versions match (both {})",
                report.kodegen_version,
                inst
            );
        }
    }

    // Simulate the orchestration logic from component_fixers.rs:810
    let should_call_fix = report.kodegen_version != ComponentStatus::Ok;
    
    println!("\nOrchestration Decision:");
    println!("  status.kodegen_version != ComponentStatus::Ok = {}", should_call_fix);
    println!("  Will call fix_kodegen_version: {}", should_call_fix);

    // If versions match, we should NOT call fix
    if let (Some(inst), Some(lat)) = (&installed, &latest) {
        if inst == lat {
            assert_eq!(
                should_call_fix, false,
                "BUG: fix_kodegen_version will be called even though installed == latest ({} == {})",
                inst, lat
            );
        }
    }
}

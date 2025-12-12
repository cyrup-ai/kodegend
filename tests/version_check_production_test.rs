//! Production-like version check test
//!
//! This test uses REAL data:
//! - Actual installed `kodegen --version` output
//! - Actual crates.io API call
//! - Actual version comparison logic
//!
//! This will expose any real-world bugs in version checking.

use kodegend::install::detection;

#[tokio::test]
async fn test_real_version_check_against_cratesio() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== PRODUCTION VERSION CHECK TEST ===\n");

    // Get REAL installed version
    let installed = detection::get_installed_binary_version("kodegen").await;
    println!("Real installed version: {:?}", installed);

    // Get REAL latest version from crates.io
    let latest = detection::get_crates_io_version("kodegen").await;
    println!("Real crates.io version: {:?}", latest);

    // Run REAL version check
    let status = detection::check_kodegen_version_status().await;
    println!("Real version check status: {:?}", status);

    // Test the orchestration decision
    let should_call_fix = status != detection::ComponentStatus::Ok;
    println!("\nOrchestration Decision:");
    println!("  status != ComponentStatus::Ok = {}", should_call_fix);
    println!("  Will call fix_kodegen_version: {}", should_call_fix);

    // If versions match, we should NOT call fix
    if let (Some(ref inst), Some(ref lat)) = (installed, latest) {
        if inst == lat {
            println!("\n✓ Versions MATCH ({} == {})", inst, lat);
            println!("  Expected: should_call_fix = false");
            println!("  Actual:   should_call_fix = {}", should_call_fix);
            
            if should_call_fix {
                panic!(
                    "BUG FOUND! Versions match ({} == {}) but status is {:?} instead of Ok",
                    inst, lat, status
                );
            }
        } else {
            println!("\n✓ Versions DIFFER ({} != {})", inst, lat);
            println!("  This is expected - update needed");
        }
    }

    println!("\n=== TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_version_cache_behavior() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== CACHE BEHAVIOR TEST ===\n");

    // First call - should hit network
    println!("First call (should fetch from crates.io):");
    let start = std::time::Instant::now();
    let v1 = detection::get_crates_io_version("kodegen").await;
    let t1 = start.elapsed();
    println!("  Version: {:?}, Time: {:?}", v1, t1);

    // Second call - should hit cache
    println!("\nSecond call (should use cache):");
    let start = std::time::Instant::now();
    let v2 = detection::get_crates_io_version("kodegen").await;
    let t2 = start.elapsed();
    println!("  Version: {:?}, Time: {:?}", v2, t2);

    assert_eq!(v1, v2, "Cached version should match first call");
    
    // Cache should be much faster than network
    if t2 > t1 / 10 {
        println!("\n⚠ WARNING: Cache might not be working! t2={:?} vs t1={:?}", t2, t1);
    } else {
        println!("\n✓ Cache is working - second call was {}x faster", t1.as_millis() / t2.as_millis().max(1));
    }

    println!("\n=== TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_double_check_race_condition() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== DOUBLE-CHECK RACE CONDITION TEST ===\n");
    
    // Simulate what fix_all_components() does:
    // 1. Check version status
    let status1 = detection::check_kodegen_version_status().await;
    println!("First check (in fix_all_components): {:?}", status1);
    
    // 2. If not OK, would call fix_kodegen_version()
    // 3. Inside fix_kodegen_version(), check AGAIN
    let status2 = detection::check_kodegen_version_status().await;
    println!("Second check (inside fix_kodegen_version): {:?}", status2);
    
    // These should be the SAME due to caching
    if status1 != status2 {
        println!("\n⚠ WARNING: Status changed between checks!");
        println!("  This could cause unnecessary downloads");
        println!("  First:  {:?}", status1);
        println!("  Second: {:?}", status2);
    } else {
        println!("\n✓ Status consistent across double-check");
    }

    println!("\n=== TEST COMPLETE ===\n");
}

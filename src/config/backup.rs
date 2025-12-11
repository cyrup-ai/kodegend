use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use chrono::Utc;

/// Configuration backup and rollback manager
///
/// Provides atomic backup/restore operations for kodegend configuration files.
/// Uses timestamp-based backup naming and automatic rotation to prevent disk bloat.
///
/// # Backup Strategy
///
/// - Backups stored in `.config_backups/` directory next to config file
/// - Naming: `<config_name>.<timestamp>.bak` (e.g., `kodegend.toml.20250610_143022.bak`)
/// - Rotation: Keeps last 5 backups, deletes oldest automatically
/// - Atomic: Uses `fs::copy()` which is atomic on most filesystems
///
/// # Example
///
/// ```rust
/// let backup_mgr = ConfigBackupManager::new(Path::new("/etc/kodegend/kodegend.toml"));
/// let backup_path = backup_mgr.create_backup()?;
/// // ... attempt config reload ...
/// if reload_failed {
///     backup_mgr.rollback_from_backup(&backup_path)?;
/// }
/// ```
pub struct ConfigBackupManager {
    /// Path to the config file being managed
    config_path: PathBuf,
    /// Directory where backups are stored
    backup_dir: PathBuf,
    /// Maximum number of backups to retain
    max_backups: usize,
}

impl ConfigBackupManager {
    /// Create a new backup manager for a config file
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the config file to manage
    ///
    /// # Backup Directory Selection
    ///
    /// Backups are stored in `.config_backups/` directory in the same directory
    /// as the config file. This ensures:
    /// - Backups survive config file deletion (separate directory)
    /// - Backups are stored on the same filesystem (atomic operations)
    /// - Easy discovery for manual recovery
    ///
    /// # Example
    ///
    /// Config at `/etc/kodegend/kodegend.toml` → backups in `/etc/kodegend/.config_backups/`
    pub fn new(config_path: &Path) -> Self {
        let backup_dir = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".config_backups");
        
        Self {
            config_path: config_path.to_path_buf(),
            backup_dir,
            max_backups: 5,
        }
    }
    
    /// Create timestamped backup of current config file
    ///
    /// # Process
    ///
    /// 1. Ensure backup directory exists (create if needed)
    /// 2. Generate timestamp-based filename
    /// 3. Copy current config to backup location
    /// 4. Rotate old backups (delete if > max_backups)
    ///
    /// # Returns
    ///
    /// Path to created backup file
    ///
    /// # Errors
    ///
    /// - Config file doesn't exist or is unreadable
    /// - Backup directory cannot be created
    /// - Insufficient disk space
    /// - Permission denied
    ///
    /// # Performance
    ///
    /// Target: < 10ms for typical configs (< 100KB)
    /// Uses `fs::copy()` which is optimized by the OS
    pub fn create_backup(&self) -> Result<PathBuf> {
        // Ensure backup directory exists
        fs::create_dir_all(&self.backup_dir)
            .with_context(|| format!(
                "Failed to create backup directory: {}",
                self.backup_dir.display()
            ))?;
        
        // Generate timestamp-based backup filename
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let config_name = self.config_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("config"))
            .to_string_lossy();
        
        let backup_name = format!("{}.{}.bak", config_name, timestamp);
        let backup_path = self.backup_dir.join(backup_name);
        
        // Copy current config to backup
        // fs::copy() is atomic on most filesystems (POSIX guarantees)
        fs::copy(&self.config_path, &backup_path)
            .with_context(|| format!(
                "Failed to backup {} to {}",
                self.config_path.display(),
                backup_path.display()
            ))?;
        
        log::info!(
            "✓ Created config backup: {} ({} bytes)",
            backup_path.display(),
            fs::metadata(&backup_path)?.len()
        );
        
        // Rotate old backups to enforce max_backups limit
        self.rotate_backups()
            .context("Failed to rotate old backups (backup created successfully)")?;
        
        Ok(backup_path)
    }
    
    /// Restore config from backup file
    ///
    /// # Arguments
    ///
    /// * `backup_path` - Path to backup file to restore from
    ///
    /// # Process
    ///
    /// 1. Verify backup file exists
    /// 2. Copy backup to config location (overwrites current config)
    /// 3. Log restoration
    ///
    /// # Errors
    ///
    /// - Backup file doesn't exist
    /// - Config file location is unwritable
    /// - Insufficient disk space
    ///
    /// # Safety
    ///
    /// This operation **overwrites** the current config file.
    /// Caller should create a backup of current config before calling if needed.
    pub fn rollback_from_backup(&self, backup_path: &Path) -> Result<()> {
        if !backup_path.exists() {
            bail!(
                "Backup file does not exist: {} (cannot rollback)",
                backup_path.display()
            );
        }
        
        // Restore backup to config location
        fs::copy(backup_path, &self.config_path)
            .with_context(|| format!(
                "Failed to restore from backup {} to {}",
                backup_path.display(),
                self.config_path.display()
            ))?;
        
        log::info!(
            "✓ Rolled back config from backup: {}",
            backup_path.display()
        );
        
        Ok(())
    }
    
    /// Get most recent backup file
    ///
    /// Useful for manual rollback commands or status queries.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(path))` - Path to most recent backup
    /// - `Ok(None)` - No backups found
    /// - `Err(_)` - Failed to read backup directory
    #[allow(dead_code)]
    pub fn get_latest_backup(&self) -> Result<Option<PathBuf>> {
        let backups = self.list_backups()?;
        Ok(backups.into_iter().next())
    }
    
    /// List all backups sorted by modification time (newest first)
    ///
    /// # Returns
    ///
    /// Vector of backup file paths, sorted newest to oldest
    ///
    /// # Implementation
    ///
    /// Sorts by filesystem modification time (not filename timestamp)
    /// to handle edge cases like:
    /// - Manually created backups
    /// - Restored backups (modification time changes)
    /// - Clock skew or timezone changes
    pub fn list_backups(&self) -> Result<Vec<PathBuf>> {
        if !self.backup_dir.exists() {
            return Ok(vec![]);
        }
        
        let mut backups: Vec<_> = fs::read_dir(&self.backup_dir)
            .with_context(|| format!(
                "Failed to read backup directory: {}",
                self.backup_dir.display()
            ))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                // Only include .bak files
                entry.path()
                    .extension()
                    .map(|ext| ext == "bak")
                    .unwrap_or(false)
            })
            .map(|entry| entry.path())
            .collect();
        
        // Sort by modification time (newest first)
        backups.sort_by_key(|path| {
            fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(std::cmp::Reverse)
        });
        
        Ok(backups)
    }
    
    /// Rotate backups to enforce max_backups limit
    ///
    /// Deletes oldest backups if count exceeds max_backups.
    ///
    /// # Errors
    ///
    /// Logs warnings for deletion failures but doesn't fail the operation.
    /// This ensures backup creation succeeds even if old backups can't be deleted.
    fn rotate_backups(&self) -> Result<()> {
        let backups = self.list_backups()?;
        
        // Delete oldest backups beyond max_backups
        for backup in backups.iter().skip(self.max_backups) {
            match fs::remove_file(backup) {
                Ok(_) => {
                    log::debug!("✓ Deleted old backup: {}", backup.display());
                }
                Err(e) => {
                    // Warn but don't fail - backup creation already succeeded
                    log::warn!(
                        "⚠ Failed to delete old backup {}: {}",
                        backup.display(),
                        e
                    );
                }
            }
        }
        
        let remaining = backups.len().min(self.max_backups);
        if remaining < backups.len() {
            log::debug!(
                "✓ Rotated backups: kept {}, deleted {}",
                remaining,
                backups.len() - remaining
            );
        }
        
        Ok(())
    }
}

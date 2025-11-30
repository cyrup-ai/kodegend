//! Windows service executable builder for kodegen
//!
//! This module creates a Windows service executable that can be embedded
//! into the main binary for cross-platform deployment.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// Build and optionally sign the Windows helper executable
pub fn build_and_sign_helper() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let exe_path = out_dir.join("KodegenHelper.exe");

    // Build Windows service executable
    create_service_executable(&exe_path)?;

    // Sign executable (optional but recommended)
    if let Err(e) = sign_executable(&exe_path) {
        eprintln!("Warning: Failed to sign executable: {}", e);
    }

    // Generate integrity hash for embedding
    generate_integrity_hash(&exe_path)?;

    println!(
        "cargo:rustc-env=WINDOWS_HELPER_EXE_PATH={}",
        exe_path.display()
    );

    Ok(())
}

/// Create the Windows service executable
fn create_service_executable(exe_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Create functional Windows helper equivalent to macOS helper
    create_functional_executable(exe_path)?;
    Ok(())
}

/// Create functional Windows helper executable using C code with Windows APIs (SECURE)
///
/// SECURITY FIX: This helper no longer executes batch scripts via cmd.exe.
/// Instead, it parses structured commands and uses Windows APIs directly.
/// This eliminates the BatBadBut vulnerability (CVE-2024-24576).
///
/// See: task/04_HIGH_windows_script_injection_uac.md
fn create_functional_executable(exe_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let helper_code = r#"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#define MAX_COMMAND_SIZE 1048576  // 1MB max
#define MAX_OPERATIONS 1000       // Prevent resource exhaustion
#define MAX_PATH_LEN 32768        // Extended path support

// Operation handlers
typedef enum {
    OP_MKDIR,
    OP_COPY,
    OP_APPEND_HOSTS,
    OP_FLUSHDNS,
    OP_UNKNOWN
} OperationType;

// Parse operation type from command string
OperationType parse_operation(const char* op_str) {
    if (strcmp(op_str, "MKDIR") == 0) return OP_MKDIR;
    if (strcmp(op_str, "COPY") == 0) return OP_COPY;
    if (strcmp(op_str, "APPEND_HOSTS") == 0) return OP_APPEND_HOSTS;
    if (strcmp(op_str, "FLUSHDNS") == 0) return OP_FLUSHDNS;
    return OP_UNKNOWN;
}

// Execute MKDIR operation using CreateDirectoryW
BOOL execute_mkdir(const char* path_utf8) {
    // Convert UTF-8 to UTF-16 for Windows API
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, path_utf8, -1, NULL, 0);
    if (wide_len == 0) {
        fprintf(stderr, "MKDIR: Failed to convert path to wide string\n");
        return FALSE;
    }
    
    WCHAR* path_wide = (WCHAR*)malloc(wide_len * sizeof(WCHAR));
    if (!path_wide) {
        fprintf(stderr, "MKDIR: Memory allocation failed\n");
        return FALSE;
    }
    
    MultiByteToWideChar(CP_UTF8, 0, path_utf8, -1, path_wide, wide_len);
    
    // Create directory (succeeds if already exists)
    BOOL result = CreateDirectoryW(path_wide, NULL);
    
    if (!result) {
        DWORD error = GetLastError();
        // ERROR_ALREADY_EXISTS is not a failure
        if (error != ERROR_ALREADY_EXISTS) {
            fprintf(stderr, "MKDIR: Failed to create directory '%s' (error %lu)\n", 
                    path_utf8, error);
            free(path_wide);
            return FALSE;
        }
    }
    
    free(path_wide);
    printf("MKDIR: Created directory '%s'\n", path_utf8);
    return TRUE;
}

// Execute COPY operation using CopyFileW
BOOL execute_copy(const char* src_utf8, const char* dst_utf8) {
    // Convert source path
    int src_wide_len = MultiByteToWideChar(CP_UTF8, 0, src_utf8, -1, NULL, 0);
    if (src_wide_len == 0) {
        fprintf(stderr, "COPY: Failed to convert source path\n");
        return FALSE;
    }
    
    WCHAR* src_wide = (WCHAR*)malloc(src_wide_len * sizeof(WCHAR));
    if (!src_wide) return FALSE;
    
    MultiByteToWideChar(CP_UTF8, 0, src_utf8, -1, src_wide, src_wide_len);
    
    // Convert destination path
    int dst_wide_len = MultiByteToWideChar(CP_UTF8, 0, dst_utf8, -1, NULL, 0);
    if (dst_wide_len == 0) {
        fprintf(stderr, "COPY: Failed to convert destination path\n");
        free(src_wide);
        return FALSE;
    }
    
    WCHAR* dst_wide = (WCHAR*)malloc(dst_wide_len * sizeof(WCHAR));
    if (!dst_wide) {
        free(src_wide);
        return FALSE;
    }
    
    MultiByteToWideChar(CP_UTF8, 0, dst_utf8, -1, dst_wide, dst_wide_len);
    
    // Copy file (FALSE = allow overwrite)
    BOOL result = CopyFileW(src_wide, dst_wide, FALSE);
    
    if (!result) {
        DWORD error = GetLastError();
        fprintf(stderr, "COPY: Failed to copy '%s' to '%s' (error %lu)\n", 
                src_utf8, dst_utf8, error);
        free(src_wide);
        free(dst_wide);
        return FALSE;
    }
    
    free(src_wide);
    free(dst_wide);
    printf("COPY: Copied '%s' to '%s'\n", src_utf8, dst_utf8);
    return TRUE;
}

// Execute APPEND_HOSTS operation using CreateFileW + WriteFile
BOOL execute_append_hosts(const char* entry_utf8) {
    // Get hosts file path
    WCHAR system_root[MAX_PATH];
    UINT len = GetSystemDirectoryW(system_root, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        fprintf(stderr, "APPEND_HOSTS: Failed to get system directory\n");
        return FALSE;
    }
    
    WCHAR hosts_path[MAX_PATH];
    if (FAILED(PathCombineW(hosts_path, system_root, L"drivers\\etc\\hosts"))) {
        fprintf(stderr, "APPEND_HOSTS: Failed to build hosts file path\n");
        return FALSE;
    }
    
    // Check if entry already exists (case-insensitive search)
    HANDLE file = CreateFileW(
        hosts_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (file != INVALID_HANDLE_VALUE) {
        // Read file and check for existing entry
        DWORD file_size = GetFileSize(file, NULL);
        if (file_size != INVALID_FILE_SIZE && file_size < 10485760) { // 10MB max
            char* buffer = (char*)malloc(file_size + 1);
            if (buffer) {
                DWORD bytes_read;
                if (ReadFile(file, buffer, file_size, &bytes_read, NULL)) {
                    buffer[bytes_read] = '\0';
                    
                    // Case-insensitive search for "mcp.kodegen.ai"
                    if (strstr(buffer, "mcp.kodegen.ai") != NULL || 
                        strstr(buffer, "MCP.KODEGEN.AI") != NULL) {
                        printf("APPEND_HOSTS: Entry already exists\n");
                        free(buffer);
                        CloseHandle(file);
                        return TRUE; // Not an error
                    }
                }
                free(buffer);
            }
        }
        CloseHandle(file);
    }
    
    // Open file for appending
    file = CreateFileW(
        hosts_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,  // Create if doesn't exist
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        fprintf(stderr, "APPEND_HOSTS: Failed to open hosts file (error %lu)\n", error);
        return FALSE;
    }
    
    // Append entry with newline
    char entry_line[512];
    int entry_len = snprintf(entry_line, sizeof(entry_line), "\n%s\n", entry_utf8);
    
    if (entry_len < 0 || entry_len >= sizeof(entry_line)) {
        fprintf(stderr, "APPEND_HOSTS: Entry too long\n");
        CloseHandle(file);
        return FALSE;
    }
    
    DWORD bytes_written;
    BOOL result = WriteFile(file, entry_line, entry_len, &bytes_written, NULL);
    
    CloseHandle(file);
    
    if (!result || bytes_written != (DWORD)entry_len) {
        DWORD error = GetLastError();
        fprintf(stderr, "APPEND_HOSTS: Failed to write entry (error %lu)\n", error);
        return FALSE;
    }
    
    printf("APPEND_HOSTS: Added entry '%s'\n", entry_utf8);
    return TRUE;
}

// Execute FLUSHDNS operation
BOOL execute_flushdns() {
    // This command has no user input, so it's safe to call via system()
    int result = system("ipconfig /flushdns >nul 2>&1");
    
    if (result != 0) {
        fprintf(stderr, "FLUSHDNS: Failed to flush DNS cache (exit code %d)\n", result);
        return FALSE;
    }
    
    printf("FLUSHDNS: DNS cache flushed\n");
    return TRUE;
}

// Validate parent process (same as before)
BOOL ValidateParentProcess() {
    DWORD current_pid = GetCurrentProcessId();
    DWORD parent_pid = 0;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Helper: Failed to create process snapshot\n");
        return FALSE;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return FALSE;
    }
    
    do {
        if (pe32.th32ProcessID == current_pid) {
            parent_pid = pe32.th32ParentProcessID;
            break;
        }
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    
    if (parent_pid == 0) {
        fprintf(stderr, "Helper: Could not find parent process\n");
        return FALSE;
    }
    
    HANDLE parent_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                      FALSE, parent_pid);
    if (!parent_handle) {
        fprintf(stderr, "Helper: Failed to open parent process\n");
        return FALSE;
    }
    
    char parent_name[MAX_PATH];
    if (!GetModuleBaseNameA(parent_handle, NULL, parent_name, sizeof(parent_name))) {
        CloseHandle(parent_handle);
        return FALSE;
    }
    
    CloseHandle(parent_handle);
    
    // Validate parent is kodegend or kodegen
    if (!strstr(parent_name, "kodegend") && !strstr(parent_name, "kodegen")) {
        fprintf(stderr, "Helper: Unauthorized parent process: %s\n", parent_name);
        return FALSE;
    }
    
    return TRUE;
}

// Main entry point
int main(int argc, char *argv[]) {
    // Validate parent process
    if (!ValidateParentProcess()) {
        ExitProcess(1);
    }
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <commands>\n", argv[0]);
        fprintf(stderr, "Commands format: OPERATION|ARG1|ARG2\\n...\n");
        ExitProcess(1);
    }
    
    const char* commands_str = argv[1];
    size_t commands_len = strlen(commands_str);
    
    if (commands_len > MAX_COMMAND_SIZE) {
        fprintf(stderr, "Helper: Commands too large (%zu bytes, max %d)\n", 
                commands_len, MAX_COMMAND_SIZE);
        ExitProcess(1);
    }
    
    // Make a mutable copy for parsing
    char* commands = (char*)malloc(commands_len + 1);
    if (!commands) {
        fprintf(stderr, "Helper: Memory allocation failed\n");
        ExitProcess(1);
    }
    strcpy(commands, commands_str);
    
    // Parse and execute commands
    int operation_count = 0;
    int failed_count = 0;
    char* line = strtok(commands, "\n");
    
    while (line != NULL && operation_count < MAX_OPERATIONS) {
        operation_count++;
        
        // Skip empty lines
        if (strlen(line) == 0) {
            line = strtok(NULL, "\n");
            continue;
        }
        
        // Parse operation and arguments
        char* op_str = strtok(line, "|");
        if (!op_str) {
            fprintf(stderr, "Helper: Invalid command format (no operation)\n");
            failed_count++;
            line = strtok(NULL, "\n");
            continue;
        }
        
        OperationType op_type = parse_operation(op_str);
        
        // Dispatch to handler
        BOOL success = FALSE;
        
        switch (op_type) {
            case OP_MKDIR: {
                char* path = strtok(NULL, "|");
                if (!path) {
                    fprintf(stderr, "MKDIR: Missing path argument\n");
                    failed_count++;
                } else {
                    success = execute_mkdir(path);
                    if (!success) failed_count++;
                }
                break;
            }
            
            case OP_COPY: {
                char* src = strtok(NULL, "|");
                char* dst = strtok(NULL, "|");
                if (!src || !dst) {
                    fprintf(stderr, "COPY: Missing source or destination argument\n");
                    failed_count++;
                } else {
                    success = execute_copy(src, dst);
                    if (!success) failed_count++;
                }
                break;
            }
            
            case OP_APPEND_HOSTS: {
                char* entry = strtok(NULL, "|");
                if (!entry) {
                    fprintf(stderr, "APPEND_HOSTS: Missing entry argument\n");
                    failed_count++;
                } else {
                    success = execute_append_hosts(entry);
                    if (!success) failed_count++;
                }
                break;
            }
            
            case OP_FLUSHDNS: {
                success = execute_flushdns();
                if (!success) failed_count++;
                break;
            }
            
            case OP_UNKNOWN:
            default: {
                fprintf(stderr, "Helper: Unknown operation '%s'\n", op_str);
                failed_count++;
                break;
            }
        }
        
        line = strtok(NULL, "\n");
    }
    
    free(commands);
    
    printf("\nHelper: Completed %d operations, %d failed\n", 
           operation_count, failed_count);
    
    // Exit with non-zero if any operations failed
    ExitProcess(failed_count > 0 ? 1 : 0);
    return 0;
}
"#;

    // Write the C source code
    let c_path = exe_path.with_extension("c");
    std::fs::write(&c_path, helper_code)?;

    // Compile with cc crate (cross-platform compiler detection)
    let mut build = cc::Build::new();
    build.file(&c_path);

    // Get the compiler to invoke it manually for full control over output path
    let compiler = build.try_get_compiler().map_err(|e| {
        format!(
            "Failed to find C compiler for Windows helper compilation: {}",
            e
        )
    })?;

    // Build the compile command with explicit output path and Windows libraries
    let mut cmd = compiler.to_command();

    // Check if this is MSVC or MinGW and set appropriate flags
    if compiler.is_like_msvc() {
        // MSVC compiler flags
        cmd.arg(format!("/Fe:{}", exe_path.display()));
        cmd.arg(&c_path);
        cmd.arg("kernel32.lib");
        cmd.arg("psapi.lib");
        cmd.arg("shlwapi.lib");
    } else {
        // MinGW/GCC compiler flags
        cmd.arg("-std=c99");
        cmd.arg("-o");
        cmd.arg(&exe_path);
        cmd.arg(&c_path);
        cmd.arg("-lkernel32");
        cmd.arg("-lpsapi");
        cmd.arg("-lshlwapi");
    }

    // Execute compilation
    let output = cmd
        .output()
        .map_err(|e| format!("Failed to execute C compiler: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to compile Windows helper: {}", stderr).into());
    }

    // Clean up temporary C file
    let _ = std::fs::remove_file(c_path);

    // Verify the executable was created - FAIL BUILD if not
    if !exe_path.exists() {
        return Err("Failed to create Windows helper executable - compilation failed".into());
    }

    Ok(())
}

/// Sign the Windows executable (optional)
fn sign_executable(exe_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Try to sign with signtool if available
    if let Ok(output) = Command::new("signtool")
        .args(&[
            "sign",
            "/a",
            "/fd",
            "SHA256",
            "/t",
            "http://timestamp.digicert.com",
            &exe_path.to_string_lossy(),
        ])
        .output()
    {
        if !output.status.success() {
            eprintln!(
                "Warning: Code signing failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            println!("Successfully signed Windows helper executable");
        }
    } else {
        eprintln!("Warning: signtool not found, executable will be unsigned");
    }

    Ok(())
}

/// Generate integrity hash for the executable
fn generate_integrity_hash(exe_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let exe_data = std::fs::read(exe_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&exe_data);
    let hash = hasher.finalize();

    let hash_hex = hex::encode(hash);
    let hash_path = exe_path.with_extension("exe.sha256");

    std::fs::write(&hash_path, &hash_hex)?;

    println!("cargo:rustc-env=WINDOWS_HELPER_EXE_HASH={}", hash_hex);

    Ok(())
}

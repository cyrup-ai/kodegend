/**
 * KodegenHelper.exe - Windows UAC Elevation Helper
 *
 * This helper executable is embedded in kodegend and extracted at runtime
 * to perform privileged operations (service installation, etc.) with UAC elevation.
 *
 * The manifest declares requireAdministrator, causing UAC prompt when run.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_CMDLINE 32768

int wmain(int argc, wchar_t *argv[]) {
    // If no arguments provided, just exit successfully
    // (The Rust code will invoke this with specific commands)
    if (argc < 2) {
        return 0;
    }

    // Rebuild command line from arguments
    wchar_t cmdline[MAX_CMDLINE] = L"";
    size_t pos = 0;

    for (int i = 1; i < argc && pos < MAX_CMDLINE - 1; i++) {
        if (i > 1) {
            cmdline[pos++] = L' ';
        }

        // Quote arguments that contain spaces
        BOOL needsQuotes = wcschr(argv[i], L' ') != NULL || wcschr(argv[i], L'\t') != NULL;
        if (needsQuotes && pos < MAX_CMDLINE - 1) {
            cmdline[pos++] = L'"';
        }

        size_t argLen = wcslen(argv[i]);
        if (pos + argLen < MAX_CMDLINE - 1) {
            wcscpy_s(cmdline + pos, MAX_CMDLINE - pos, argv[i]);
            pos += argLen;
        }

        if (needsQuotes && pos < MAX_CMDLINE - 1) {
            cmdline[pos++] = L'"';
        }
    }
    cmdline[pos] = L'\0';

    // Execute the command with elevated privileges
    // (We're already elevated due to manifest, so this runs with admin rights)
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL success = CreateProcessW(
        NULL,           // Application name (use command line)
        cmdline,        // Command line
        NULL,           // Process security attributes
        NULL,           // Thread security attributes
        FALSE,          // Inherit handles
        0,              // Creation flags
        NULL,           // Environment
        NULL,           // Current directory
        &si,            // Startup info
        &pi             // Process information
    );

    if (!success) {
        return GetLastError();
    }

    // Wait for the process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Get exit code
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exitCode;
}

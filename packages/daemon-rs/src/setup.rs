// Cross-platform daemon auto-start registration.
// Installs (or removes) the ANUBIS daemon as a login service on Windows,
// macOS, and Linux. All shell-out commands use std::process::Command so the
// crate has no extra system dependencies.

use std::path::PathBuf;

const DAEMON_LABEL: &str = "anubis-daemon";

/// Install the daemon to run at login on the current platform.
pub fn setup_daemon(daemon_path: &str, port: u16, host: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        return setup_windows(daemon_path, port, host);
    }
    #[cfg(target_os = "macos")]
    {
        return setup_macos(daemon_path, port, host);
    }
    #[cfg(target_os = "linux")]
    {
        return setup_linux(daemon_path, port, host);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (daemon_path, port, host);
        Err("unsupported platform".into())
    }
}

/// Remove the daemon from login auto-start on the current platform.
pub fn uninstall_daemon() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        return uninstall_windows();
    }
    #[cfg(target_os = "macos")]
    {
        return uninstall_macos();
    }
    #[cfg(target_os = "linux")]
    {
        return uninstall_linux();
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}

// ---------------------------------------------------------------------------
// Windows: Startup folder shortcut (.lnk). No admin needed.
// anubis-daemon.exe has windows_subsystem = "windows" → no console window.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn setup_windows(daemon_path: &str, port: u16, host: &str) -> Result<(), String> {
    let appdata = std::env::var("APPDATA").map_err(|_| "APPDATA not set".to_string())?;
    let startup_dir = PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup");
    std::fs::create_dir_all(&startup_dir).map_err(|e| format!("create startup dir: {e}"))?;

    // Create .lnk shortcut via PowerShell COM object (creates proper Windows shortcut)
    let lnk_path = startup_dir.join(format!("{DAEMON_LABEL}.lnk"));
    let args = format!("--port {port} --host {host}");
    let ps_script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{}'); \
         $s.TargetPath = '{}'; \
         $s.Arguments = '{}'; \
         $s.WindowStyle = 7; \
         $s.Description = 'anubis background daemon'; \
         $s.Save()",
        lnk_path.to_string_lossy(),
        daemon_path,
        args
    );

    let result = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output()
        .map_err(|e| format!("run powershell: {e}"))?;

    if !result.status.success() {
        return Err(format!(
            "shortcut creation failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows() -> Result<(), String> {
    // Remove Startup shortcut
    if let Ok(appdata) = std::env::var("APPDATA") {
        let lnk_path = PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup")
            .join(format!("{DAEMON_LABEL}.lnk"));
        if lnk_path.exists() {
            let _ = std::fs::remove_file(&lnk_path);
        }
        // Also clean up old .bat from previous versions
        let bat_path = lnk_path.with_extension("bat");
        if bat_path.exists() {
            let _ = std::fs::remove_file(&bat_path);
        }
    }

    // Remove old Run key if present from previous versions
    let _ = std::process::Command::new("reg.exe")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            DAEMON_LABEL,
            "/f",
        ])
        .output();

    // Best-effort cleanup of legacy URL scheme registration (pre-removal versions
    // registered anubis:// — removed because opening terminal from browser felt
    // like malware behavior to users).
    let _ = std::process::Command::new("reg.exe")
        .args(["delete", r"HKCU\Software\Classes\anubis", "/f"])
        .output();

    Ok(())
}

// ---------------------------------------------------------------------------
// macOS: per-user LaunchAgent plist + launchctl load.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn setup_macos(daemon_path: &str, port: u16, host: &str) -> Result<(), String> {
    let launch_dir = home_dir().join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&launch_dir).map_err(|e| format!("create LaunchAgents dir: {e}"))?;

    let plist_path = launch_dir.join("ai.anubis.daemon.plist");
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>daemon</string>
        <string>--port</string>
        <string>{port}</string>
        <string>--host</string>
        <string>{host}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"#,
        label = DAEMON_LABEL,
        exe = daemon_path,
        port = port,
        host = host,
    );

    std::fs::write(&plist_path, plist_content)
        .map_err(|e| format!("write {}: {e}", plist_path.display()))?;

    // Unload first (idempotent if not loaded) so we don't get duplicate agents.
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &plist_path.to_string_lossy()])
        .output();

    let result = std::process::Command::new("launchctl")
        .args(["load", &plist_path.to_string_lossy()])
        .output()
        .map_err(|e| format!("run launchctl load: {e}"))?;
    if !result.status.success() {
        return Err(format!(
            "launchctl load failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_macos() -> Result<(), String> {
    let plist_path = home_dir()
        .join("Library")
        .join("LaunchAgents")
        .join("ai.anubis.daemon.plist");
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .output();
        let _ = std::fs::remove_file(&plist_path);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux: per-user systemd service + enable.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn setup_linux(daemon_path: &str, port: u16, host: &str) -> Result<(), String> {
    let systemd_dir = home_dir().join(".config").join("systemd").join("user");
    std::fs::create_dir_all(&systemd_dir).map_err(|e| format!("create systemd user dir: {e}"))?;

    let service_path = systemd_dir.join(format!("{DAEMON_LABEL}.service"));
    let service_content = format!(
        "[Unit]\n\
         Description=ANUBIS Hallucination Detection Daemon\n\
         After=network.target\n\
         \n\
         [Service]\n\
         ExecStart={exe} daemon --port {port} --host {host}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = daemon_path,
        port = port,
        host = host,
    );

    std::fs::write(&service_path, service_content)
        .map_err(|e| format!("write {}: {e}", service_path.display()))?;

    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output()
        .map_err(|e| format!("run systemctl daemon-reload: {e}"))?;
    if !reload.status.success() {
        return Err(format!(
            "systemctl daemon-reload failed: {}",
            String::from_utf8_lossy(&reload.stderr).trim()
        ));
    }

    let enable = std::process::Command::new("systemctl")
        .args(["--user", "enable", DAEMON_LABEL])
        .output()
        .map_err(|e| format!("run systemctl enable: {e}"))?;
    if !enable.status.success() {
        return Err(format!(
            "systemctl enable failed: {}",
            String::from_utf8_lossy(&enable.stderr).trim()
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_linux() -> Result<(), String> {
    // Best-effort disable, then remove the unit and reload.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", DAEMON_LABEL])
        .output();

    let service_path = home_dir()
        .join(".config")
        .join("systemd")
        .join("user")
        .join(format!("{DAEMON_LABEL}.service"));
    if service_path.exists() {
        let _ = std::fs::remove_file(&service_path);
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .ok()
        .or_else(|| std::env::var("HOME").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

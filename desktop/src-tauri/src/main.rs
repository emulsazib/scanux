//! Scanu desktop client (tray app).
//!
//! * Talks to the local sensor service over `\\.\pipe\scanu-desktop` (JSON lines,
//!   both ways): scans, threats found, and the narrow local actions the sensor
//!   allows (quarantine flagged files, terminate frozen processes). Works with no
//!   cloud at all.
//! * Optionally talks to a Scanu cloud API (configured in Settings) for
//!   Tier-2/3 decisions; those commands are signed by the cloud, never by this app.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

/// Write half of the pipe while the sensor is connected.
#[derive(Default)]
struct Sensor(Mutex<Option<std::fs::File>>);

/// Request types the UI may forward. The sensor enforces its own (stricter) rules too.
const ALLOWED: &[&str] = &["status", "scan", "cancel_scan", "findings", "quarantine", "terminate"];

#[tauri::command]
fn sensor_request(state: tauri::State<'_, Sensor>, request: serde_json::Value) -> Result<(), String> {
    use std::io::Write;
    let cmd = request["cmd"].as_str().ok_or("missing cmd")?;
    if !ALLOWED.contains(&cmd) {
        return Err(format!("unsupported request {cmd}"));
    }
    let mut guard = state.0.lock().map_err(|_| "sensor link poisoned")?;
    let pipe = guard.as_mut().ok_or("The Scanu sensor service is not running")?;
    writeln!(pipe, "{request}").map_err(|e| e.to_string())
}

#[cfg(windows)]
mod pipe {
    use super::Sensor;
    use std::io::{BufRead, BufReader, Write};
    use std::time::Duration;
    use tauri::{AppHandle, Emitter, Manager};
    use tauri_plugin_notification::NotificationExt;

    const PIPE: &str = r"\\.\pipe\scanu-desktop";

    fn file_name(p: &str) -> &str {
        p.rsplit('\\').next().unwrap_or(p)
    }

    fn notify(app: &AppHandle, v: &serde_json::Value) {
        let (title, body) = match v["type"].as_str() {
            Some("frozen") => (
                "Scanu stopped a threat",
                format!("{} was paused and cut off from the network. Open Scanu to remove it.", file_name(v["image"].as_str().unwrap_or("A program"))),
            ),
            Some("blocked") => ("Scanu blocked a program", format!("{} was stopped as it started.", file_name(v["image"].as_str().unwrap_or("A program")))),
            Some("finding") => ("Scanu found a threat", format!("{} — open Scanu to quarantine it.", file_name(v["path"].as_str().unwrap_or("A file")))),
            _ => return,
        };
        let _ = app.notification().builder().title(title).body(body).show();
    }

    pub fn spawn(app: AppHandle) {
        std::thread::spawn(move || loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(PIPE) {
                Ok(f) => {
                    let Ok(mut writer) = f.try_clone() else { continue };
                    let _ = writeln!(writer, r#"{{"cmd":"status"}}"#);
                    let _ = writeln!(writer, r#"{{"cmd":"findings"}}"#);
                    *app.state::<Sensor>().0.lock().unwrap() = Some(writer);
                    let _ = app.emit("sensor-link", true);
                    for line in BufReader::new(f).lines().map_while(Result::ok) {
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                        notify(&app, &v);
                        let _ = app.emit("sensor-notice", v);
                    }
                    *app.state::<Sensor>().0.lock().unwrap() = None;
                    let _ = app.emit("sensor-link", false);
                }
                Err(_) => std::thread::sleep(Duration::from_secs(2)), // service starting / not installed
            }
        });
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(Sensor::default())
        .invoke_handler(tauri::generate_handler![sensor_request])
        .setup(|app| {
            #[cfg(windows)]
            pipe::spawn(app.handle().clone());
            let icon = app.default_window_icon().cloned().expect("bundled icon");
            TrayIconBuilder::new()
                .icon(icon)
                .tooltip("Scanu")
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps Scanu in the tray; the sensor runs regardless.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to start Scanu desktop");
}

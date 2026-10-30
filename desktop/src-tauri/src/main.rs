//! Scanu desktop client. The UI (../ui) polls the API for Tier-2 prompts; on
//! Windows this process also reads the sensor's named pipe for instant
//! "frozen/blocked" notices. The pipe is read-only from here: a choice made in
//! the UI goes to the cloud API, which signs the command the sensor will run.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

#[cfg(windows)]
mod pipe {
    use std::io::{BufRead, BufReader};
    use std::time::Duration;
    use tauri::{AppHandle, Emitter};
    use tauri_plugin_notification::NotificationExt;

    const PIPE: &str = r"\\.\pipe\scanu-desktop";

    pub fn spawn(app: AppHandle) {
        std::thread::spawn(move || loop {
            match std::fs::File::open(PIPE) {
                Ok(f) => {
                    for line in BufReader::new(f).lines().map_while(Result::ok) {
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                        if v["type"] == "frozen" || v["type"] == "blocked" {
                            let image = v["image"].as_str().unwrap_or("a program");
                            let name = image.rsplit('\\').next().unwrap_or(image);
                            let body = if v["type"] == "frozen" {
                                format!("{name} was paused and cut off from the network. Open Scanu to decide what happens next.")
                            } else {
                                format!("{name} was blocked before it could start.")
                            };
                            let _ = app.notification().builder().title("Scanu stopped a threat").body(body).show();
                        }
                        let _ = app.emit("sensor-notice", v);
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_secs(2)), // sensor not running yet
            }
        });
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            #[cfg(windows)]
            pipe::spawn(app.handle().clone());
            let icon = app.default_window_icon().cloned().expect("bundled icon");
            TrayIconBuilder::new()
                .icon(icon)
                .tooltip("Scanu: protected")
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
        .run(tauri::generate_context!())
        .expect("failed to start Scanu desktop");
}

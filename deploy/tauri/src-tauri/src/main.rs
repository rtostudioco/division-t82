// DIVISION T82 · Shell de escritorio (Tauri 2)
//
// Lanza el servidor Next.js standalone como "sidecar" (node-runtime + server.js),
// espera a que el puerto local responda y abre una ventana webview apuntando a
// http://127.0.0.1:<puerto>. Al cerrar la ventana, el servidor se detiene.
//
// Datos SQLite: directorio local de datos de la app por plataforma
//   (%LOCALAPPDATA%, ~/Library/Application Support, ~/.local/share).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use tauri::Manager;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

struct ServerHandle(Mutex<Option<CommandChild>>);

fn stop_server(handle: &tauri::AppHandle) {
    if let Some(state) = handle.try_state::<ServerHandle>() {
        if let Ok(mut guard) = state.0.lock() {
            if let Some(child) = guard.take() {
                let _ = child.kill();
            }
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let port: u16 = std::env::var("T82_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(43182);

            let app_dir = app
                .path()
                .resource_dir()
                .map_err(|e| format!("no se resolvió el directorio de recursos: {e}"))?
                .join("app");
            let data_dir = app
                .path()
                .app_local_data_dir()
                .map_err(|e| format!("no se resolvió el directorio de datos: {e}"))?;
            std::fs::create_dir_all(&data_dir)
                .map_err(|e| format!("no se pudo crear el directorio de datos: {e}"))?;
            let db_url = format!(
                "file:{}/vulncheck.db",
                data_dir.to_string_lossy().replace('\\', "/")
            );

            // db push idempotente antes del arranque (CLI Prisma empaquetada)
            let prisma_cli = app
                .path()
                .resource_dir()
                .map_err(|e| format!("recursos: {e}"))?
                .join("tools/prisma-cli/node_modules/prisma/build/index.js");
            let _ = std::process::Command::new(
                app.path().resource_dir()?.join("binaries").join(if cfg!(windows) {
                    "node-runtime.exe"
                } else {
                    "node-runtime"
                }),
            )
            .arg(&prisma_cli)
            .arg("db")
            .arg("push")
            .arg("--skip-generate")
            .env("DATABASE_URL", &db_url)
            .current_dir(&app_dir)
            .status();

            let sidecar = app
                .shell()
                .sidecar("node-runtime")
                .map_err(|e| format!("sidecar node-runtime: {e}"))?;
            let (_rx, child) = sidecar
                .args(["server.js"])
                .current_dir(&app_dir)
                .env("NODE_ENV", "production")
                .env("PORT", port.to_string())
                .env("HOSTNAME", "127.0.0.1")
                .env("DATABASE_URL", db_url)
                .spawn()
                .map_err(|e| format!("no se pudo arrancar el servidor T82: {e}"))?;
            app.manage(ServerHandle(Mutex::new(Some(child))));

            // Espera de salud: hasta 45 s a que el puerto local acepte conexiones
            let deadline = Instant::now() + Duration::from_secs(45);
            let mut ready = false;
            while Instant::now() < deadline {
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    ready = true;
                    break;
                }
                thread::sleep(Duration::from_millis(400));
            }
            if !ready {
                stop_server(app.handle());
                return Err("el servidor DIVISION T82 no respondió en 45 s".into());
            }

            let url = tauri::url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
            tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::External(url))
                .title("DIVISION T82 · By: Ramón Taboada Olivella (RTO Studio)")
                .inner_size(1280.0, 840.0)
                .min_inner_size(960.0, 600.0)
                .build()
                .map_err(|e| format!("ventana: {e}"))?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                stop_server(window.app_handle());
            }
        })
        .on_page_load(|_webview, _payload| {})
        .run(tauri::generate_context!())
        .expect("error al ejecutar DIVISION T82");
}

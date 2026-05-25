mod crypto;
mod desktop_overlay;
mod network;

use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use network::{DeviceInfo, Identity, NetworkService, TransferEvent, TransferReceipt};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
#[cfg(not(mobile))]
use tauri::{WebviewUrl, WebviewWindowBuilder};

struct AppState {
    network: Arc<NetworkService>,
    receive_dir: Mutex<PathBuf>,
    settings_path: Mutex<PathBuf>,
    overlay: Arc<desktop_overlay::OverlayState>,
}

pub struct PublishedFile {
    pub uri: String,
}

#[derive(Default, Deserialize, Serialize)]
struct AppSettings {
    device_name: Option<String>,
}

#[tauri::command]
fn device_identity(state: State<'_, AppState>) -> Identity {
    state.network.identity()
}

#[tauri::command]
fn list_devices(state: State<'_, AppState>) -> Vec<DeviceInfo> {
    state.network.devices()
}

#[tauri::command]
fn set_device_name(name: String, state: State<'_, AppState>) -> Result<Identity, String> {
    let identity = state.network.set_device_name(name)?;
    let settings = AppSettings {
        device_name: Some(identity.name.clone()),
    };
    let settings_path = state
        .settings_path
        .lock()
        .map_err(|_| "设置路径状态异常".to_string())?
        .clone();
    write_settings(&settings_path, &settings)?;
    Ok(identity)
}

#[tauri::command]
async fn send_files(
    paths: Vec<String>,
    target_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<TransferReceipt>, String> {
    let network = state.network.clone();
    tauri::async_runtime::spawn_blocking(move || network.send_files(paths, target_id))
        .await
        .map_err(|error| format!("发送任务异常：{error}"))?
}

#[tauri::command]
fn transfer_history(state: State<'_, AppState>) -> Vec<TransferEvent> {
    state.network.transfer_history()
}

#[tauri::command]
fn clear_transfer_history(state: State<'_, AppState>) {
    state.network.clear_transfer_history();
}

#[tauri::command]
#[cfg(target_os = "android")]
fn receive_dir() -> Result<String, String> {
    Ok("Download/File Sharer".to_string())
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
fn receive_dir(state: State<'_, AppState>) -> Result<String, String> {
    let receive_dir = state
        .receive_dir
        .lock()
        .map_err(|_| "接收目录状态异常".to_string())?
        .clone();
    Ok(receive_dir.display().to_string())
}

#[tauri::command]
#[cfg(target_os = "android")]
fn open_receive_dir(app: tauri::AppHandle) -> Result<(), String> {
    native_opener::open_downloads(&app)
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
fn open_receive_dir(state: State<'_, AppState>, app: tauri::AppHandle) -> Result<(), String> {
    let receive_dir = state
        .receive_dir
        .lock()
        .map_err(|_| "接收目录状态异常".to_string())?
        .clone();
    std::fs::create_dir_all(&receive_dir).map_err(|error| format!("创建接收目录失败：{error}"))?;
    open_path_with_system(app, &receive_dir)
}

#[tauri::command]
fn record_sent_transfer(
    file_name: String,
    peer_name: String,
    bytes: u64,
    state: State<'_, AppState>,
) {
    state
        .network
        .record_sent_transfer(file_name, peer_name, bytes);
}

#[tauri::command]
fn cancel_transfer(transfer_id: String, state: State<'_, AppState>) {
    state.network.cancel_transfer(transfer_id);
}

#[tauri::command]
fn open_saved_file(
    path: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        if path.starts_with("content://media/") {
            return native_opener::open_uri(&app, &path);
        }
        if path.starts_with("content://") {
            return Err("只能打开本应用接收到的文件".to_string());
        }
    }

    let receive_dir = state
        .receive_dir
        .lock()
        .map_err(|_| "接收目录状态异常".to_string())?
        .clone();
    let path = PathBuf::from(path);
    ensure_saved_file_path(&receive_dir, &path)?;
    open_path_with_system(app, &path)
}

#[tauri::command]
fn set_overlay_busy(busy: bool, state: State<'_, AppState>) {
    state.overlay.set_busy(busy);
}

#[tauri::command]
fn show_overlay(app: tauri::AppHandle) {
    desktop_overlay::show_overlay_window(&app);
}

#[tauri::command]
fn hide_overlay(app: tauri::AppHandle, state: State<'_, AppState>) {
    if !state.overlay.is_busy() {
        resize_overlay_window(&app, "normal");
        desktop_overlay::hide_overlay_window(&app);
    }
}

#[tauri::command]
fn set_overlay_mode(mode: String, app: tauri::AppHandle) {
    resize_overlay_window(&app, &mode);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let network = NetworkService::new();
    let overlay = Arc::new(desktop_overlay::OverlayState::new());

    tauri::Builder::default()
        .plugin(native_opener::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            network: network.clone(),
            receive_dir: Mutex::new(default_receive_dir()),
            settings_path: Mutex::new(default_settings_path()),
            overlay: overlay.clone(),
        })
        .setup(move |app| {
            let resolved_receive_dir = resolve_receive_dir(app);
            let resolved_settings_path = resolve_settings_path(app);
            if let Ok(settings) = read_settings(&resolved_settings_path) {
                if let Some(device_name) = settings.device_name {
                    let _ = network.set_device_name(device_name);
                }
            }
            network.set_receive_dir(resolved_receive_dir.clone());
            network.set_app_handle(app.handle().clone());
            if let Ok(mut state_dir) = app.state::<AppState>().receive_dir.lock() {
                *state_dir = resolved_receive_dir.clone();
            }
            if let Ok(mut settings_path) = app.state::<AppState>().settings_path.lock() {
                *settings_path = resolved_settings_path.clone();
            }
            network.start();
            #[cfg(not(mobile))]
            {
                let overlay_window = WebviewWindowBuilder::new(
                    app,
                    "overlay",
                    WebviewUrl::App("index.html?window=overlay".into()),
                )
                .title("File Sharer Drop Target")
                .inner_size(456.0, 116.0)
                .resizable(false)
                .decorations(false)
                .transparent(true)
                .always_on_top(true)
                .skip_taskbar(true)
                .visible(false)
                .focused(false)
                .focusable(false)
                .shadow(false)
                .build()?;
                desktop_overlay::position_overlay_window(&overlay_window);
                desktop_overlay::hide_overlay_window(app.handle());
                desktop_overlay::start_drag_monitor(app.handle().clone(), overlay.clone());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            device_identity,
            list_devices,
            set_device_name,
            send_files,
            transfer_history,
            clear_transfer_history,
            receive_dir,
            open_receive_dir,
            record_sent_transfer,
            cancel_transfer,
            open_saved_file,
            set_overlay_busy,
            show_overlay,
            hide_overlay,
            set_overlay_mode
        ])
        .run(tauri::generate_context!())
        .expect("error while running File Sharer");
}

fn resolve_receive_dir<R: tauri::Runtime>(app: &tauri::App<R>) -> std::path::PathBuf {
    app.path()
        .download_dir()
        .or_else(|_| app.path().app_data_dir())
        .unwrap_or_else(|_| env::temp_dir())
        .join("File Sharer")
}

fn default_receive_dir() -> PathBuf {
    env::temp_dir().join("File Sharer")
}

#[cfg(target_os = "android")]
pub fn publish_received_file(app: &Option<tauri::AppHandle>, path: &Path) -> Option<PublishedFile> {
    let app = app.as_ref()?;
    native_opener::publish_to_downloads(app, path)
        .ok()
        .map(|published| PublishedFile { uri: published.uri })
}

#[cfg(not(target_os = "android"))]
pub fn publish_received_file(
    _app: &Option<tauri::AppHandle>,
    _path: &Path,
) -> Option<PublishedFile> {
    None
}

fn resolve_settings_path<R: tauri::Runtime>(app: &tauri::App<R>) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| env::temp_dir().join("File Sharer"))
        .join("settings.json")
}

fn default_settings_path() -> PathBuf {
    env::temp_dir().join("File Sharer").join("settings.json")
}

fn read_settings(path: &Path) -> Result<AppSettings, String> {
    let content = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&content).map_err(|error| error.to_string())
}

fn write_settings(path: &Path, settings: &AppSettings) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("创建设置目录失败：{error}"))?;
    }
    let content = serde_json::to_string_pretty(settings).map_err(|error| error.to_string())?;
    std::fs::write(path, content).map_err(|error| format!("保存设置失败：{error}"))
}

fn resize_overlay_window(app: &tauri::AppHandle, mode: &str) {
    let Some(window) = app.get_webview_window("overlay") else {
        return;
    };
    desktop_overlay::resize_overlay_for_mode(&window, mode);
}

fn ensure_saved_file_path(receive_dir: &Path, path: &Path) -> Result<(), String> {
    let receive_dir = receive_dir
        .canonicalize()
        .map_err(|error| format!("接收目录无效：{error}"))?;
    let path = path
        .canonicalize()
        .map_err(|error| format!("文件不存在：{error}"))?;

    if !path.starts_with(&receive_dir) {
        return Err("只能打开本应用接收到的文件".to_string());
    }

    if !path.is_file() {
        return Err("只能打开文件".to_string());
    }

    Ok(())
}

#[cfg(not(target_os = "android"))]
fn open_path_with_system(app: tauri::AppHandle, path: &Path) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    app.opener()
        .open_path(path.display().to_string(), None::<String>)
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "android")]
fn open_path_with_system(app: tauri::AppHandle, path: &Path) -> Result<(), String> {
    native_opener::open_path(&app, path)
}

mod native_opener {
    #[cfg(target_os = "android")]
    use std::{path::Path, sync::Mutex};

    #[cfg(target_os = "android")]
    use serde::Deserialize;
    #[cfg(target_os = "android")]
    use serde::Serialize;
    #[cfg(target_os = "android")]
    use tauri::plugin::mobile::PluginInvokeError;
    use tauri::{plugin::TauriPlugin, Manager};

    pub struct NativeOpener {
        #[cfg(target_os = "android")]
        handle: Mutex<Option<tauri::plugin::PluginHandle<tauri::Wry>>>,
    }

    impl NativeOpener {
        #[cfg(target_os = "android")]
        fn open_path(&self, path: &Path) -> Result<(), PluginInvokeError> {
            let handle = self.handle.lock().expect("native opener poisoned");
            let handle = handle.as_ref().expect("native opener not initialized");
            handle.run_mobile_plugin::<()>(
                "openPath",
                OpenPathArgs {
                    path: path.display().to_string(),
                },
            )
        }

        #[cfg(target_os = "android")]
        fn open_uri(&self, uri: &str) -> Result<(), PluginInvokeError> {
            let handle = self.handle.lock().expect("native opener poisoned");
            let handle = handle.as_ref().expect("native opener not initialized");
            handle.run_mobile_plugin::<()>(
                "openUri",
                OpenUriArgs {
                    uri: uri.to_string(),
                },
            )
        }

        #[cfg(target_os = "android")]
        fn open_downloads(&self) -> Result<(), PluginInvokeError> {
            let handle = self.handle.lock().expect("native opener poisoned");
            let handle = handle.as_ref().expect("native opener not initialized");
            handle.run_mobile_plugin::<()>("openDownloads", ())
        }

        #[cfg(target_os = "android")]
        fn publish_to_downloads(&self, path: &Path) -> Result<PublishedFile, PluginInvokeError> {
            let handle = self.handle.lock().expect("native opener poisoned");
            let handle = handle.as_ref().expect("native opener not initialized");
            handle.run_mobile_plugin::<PublishedFile>(
                "publishToDownloads",
                OpenPathArgs {
                    path: path.display().to_string(),
                },
            )
        }
    }

    #[cfg(target_os = "android")]
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OpenPathArgs {
        path: String,
    }

    #[cfg(target_os = "android")]
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OpenUriArgs {
        uri: String,
    }

    #[cfg(target_os = "android")]
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PublishedFile {
        pub uri: String,
    }

    #[cfg(target_os = "android")]
    pub fn open_path(app: &tauri::AppHandle, path: &Path) -> Result<(), String> {
        app.state::<NativeOpener>()
            .open_path(path)
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "android")]
    pub fn open_uri(app: &tauri::AppHandle, uri: &str) -> Result<(), String> {
        app.state::<NativeOpener>()
            .open_uri(uri)
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "android")]
    pub fn open_downloads(app: &tauri::AppHandle) -> Result<(), String> {
        app.state::<NativeOpener>()
            .open_downloads()
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "android")]
    pub fn publish_to_downloads(
        app: &tauri::AppHandle,
        path: &Path,
    ) -> Result<PublishedFile, String> {
        app.state::<NativeOpener>()
            .publish_to_downloads(path)
            .map_err(|error| error.to_string())
    }

    pub fn init() -> TauriPlugin<tauri::Wry> {
        tauri::plugin::Builder::<tauri::Wry>::new("native-opener")
            .setup(|app, _api| {
                #[cfg(target_os = "android")]
                {
                    let handle =
                        _api.register_android_plugin("dev.fang.file_sharer", "NativeOpenerPlugin")?;
                    app.manage(NativeOpener {
                        handle: Mutex::new(Some(handle)),
                    });
                }

                #[cfg(not(target_os = "android"))]
                {
                    app.manage(NativeOpener {});
                }

                Ok(())
            })
            .build()
    }
}

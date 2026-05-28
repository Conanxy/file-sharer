use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use tauri::Emitter;
use tauri::{AppHandle, LogicalSize, Manager, PhysicalPosition, Runtime, Size};

pub struct OverlayState {
    busy: AtomicBool,
    mode: Mutex<String>,
}

impl OverlayState {
    pub fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            mode: Mutex::new("normal".to_string()),
        }
    }

    pub fn set_busy(&self, busy: bool) {
        self.busy.store(busy, Ordering::SeqCst);
    }

    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    pub fn set_mode(&self, mode: &str) {
        let mut current_mode = self.mode.lock().expect("overlay mode poisoned");
        *current_mode = mode.to_string();
    }

    pub fn mode(&self) -> String {
        self.mode.lock().expect("overlay mode poisoned").clone()
    }
}

pub fn show_overlay_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("overlay") else {
        return;
    };

    resize_overlay_for_mode(&window, "drag");
    position_overlay_window(&window);
    let _ = window.show();
    let _ = window.set_focusable(false);
}

pub fn hide_overlay_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("overlay") else {
        return;
    };

    let _ = window.set_focusable(false);
    let _ = window.hide();
}

pub fn position_overlay_window<R: Runtime>(window: &tauri::WebviewWindow<R>) {
    let Ok(Some(monitor)) = window
        .current_monitor()
        .or_else(|_| window.primary_monitor())
    else {
        return;
    };

    let Ok(size) = window.outer_size() else {
        return;
    };

    let monitor_position = monitor.position();
    let monitor_size = monitor.size();
    let x = monitor_position.x + monitor_size.width as i32 - size.width as i32 - 24;
    let y = monitor_position.y + 32;
    let _ = window.set_position(PhysicalPosition::new(x, y));
}

pub fn resize_overlay_for_mode<R: Runtime>(window: &tauri::WebviewWindow<R>, mode: &str) {
    let (width, height) = match mode {
        "drag" => (560.0, 300.0),
        "transfer" => (456.0, 128.0),
        "confirm" => (560.0, 300.0),
        _ => (456.0, 116.0),
    };
    let _ = window.set_size(Size::Logical(LogicalSize::new(width, height)));
    position_overlay_window(window);
}

#[cfg(target_os = "macos")]
pub fn start_drag_monitor(app: AppHandle, state: Arc<OverlayState>) {
    std::thread::spawn(move || {
        let mut visible = false;
        let mut last_seen = Instant::now();
        let mut seen_change_count = macos_drag_pasteboard_state().change_count;
        let mut active_change_count = None;

        loop {
            let mouse_down = macos_left_mouse_down();
            let drag_state = macos_drag_pasteboard_state();
            let new_file_drag = mouse_down
                && drag_state.has_file_url
                && drag_state.change_count != seen_change_count;
            let continuing_file_drag = mouse_down
                && visible
                && drag_state.has_file_url
                && active_change_count == Some(drag_state.change_count);

            if new_file_drag {
                seen_change_count = drag_state.change_count;
                active_change_count = Some(drag_state.change_count);
                last_seen = Instant::now();
                let _ = app.emit_to("overlay", "desktop-file-drag", true);
                if !state.is_busy() {
                    show_overlay_window(&app);
                }
                visible = true;
            } else if continuing_file_drag {
                last_seen = Instant::now();
            } else if visible && last_seen.elapsed() > Duration::from_millis(700) && !state.is_busy() {
                let _ = app.emit_to("overlay", "desktop-file-drag", false);
                hide_overlay_window(&app);
                visible = false;
                active_change_count = None;
                seen_change_count = drag_state.change_count;
            } else if !mouse_down && !visible {
                active_change_count = None;
                seen_change_count = drag_state.change_count;
            }

            std::thread::sleep(Duration::from_millis(120));
        }
    });
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct DragPasteboardState {
    change_count: isize,
    has_file_url: bool,
}

#[cfg(target_os = "macos")]
fn macos_drag_pasteboard_state() -> DragPasteboardState {
    use objc2_app_kit::{NSPasteboard, NSPasteboardNameDrag, NSPasteboardTypeFileURL};
    use objc2_foundation::NSArray;

    let pasteboard = NSPasteboard::pasteboardWithName(unsafe { NSPasteboardNameDrag });
    let change_count = pasteboard.changeCount() as isize;
    let types = NSArray::arrayWithObject(unsafe { NSPasteboardTypeFileURL });
    let has_file_url = pasteboard.availableTypeFromArray(&types).is_some();

    DragPasteboardState {
        change_count,
        has_file_url,
    }
}

#[cfg(target_os = "macos")]
fn macos_left_mouse_down() -> bool {
    use core_graphics::event_source::CGEventSourceStateID;

    const LEFT_MOUSE_BUTTON: u32 = 0;

    unsafe extern "C" {
        fn CGEventSourceButtonState(state_id: CGEventSourceStateID, button: u32) -> bool;
    }

    unsafe {
        CGEventSourceButtonState(
            CGEventSourceStateID::CombinedSessionState,
            LEFT_MOUSE_BUTTON,
        )
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub fn start_drag_monitor(_app: AppHandle, _state: Arc<OverlayState>) {}

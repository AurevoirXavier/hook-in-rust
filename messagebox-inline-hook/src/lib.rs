#[macro_use]
extern crate detour;
extern crate winapi;

use std::ptr::null_mut;
use winapi::shared::{
    minwindef::LPVOID,
    ntdef::LPCWSTR,
    windef::HWND,
};

static_detour! {
    static MessageBoxWHook: unsafe extern "system" fn(HWND, LPCWSTR, LPCWSTR, u32) -> i32;
}

type MessageBoxW = unsafe extern "system" fn(HWND, LPCWSTR, LPCWSTR, u32) -> i32;

unsafe fn clear_last_error() {
    use winapi::um::errhandlingapi::SetLastError;
    SetLastError(0);
}

unsafe fn show_last_error() {
    use winapi::um::{
        errhandlingapi::GetLastError,
        winuser::{MB_OK, MessageBoxA},
    };

    let e = GetLastError();
    let e = format!("{}\0", e.to_string());
    MessageBoxA(null_mut(), e.as_ptr() as _, "\0".as_ptr() as _, MB_OK);
}

fn hook_message_box_w(h_wnd: HWND, _: LPCWSTR, _: LPCWSTR, u_type: u32) -> i32 {
    unsafe {
        MessageBoxWHook.call(
            h_wnd,
            "Ops hooked by detour-rs!\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
            "Ops hooked by detour-rs!\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
            u_type,
        )
    }
}

unsafe fn detour_message_box_w() {
    use winapi::um::libloaderapi::GetModuleHandleA;

    let module_address = GetModuleHandleA("USER32.dll\0".as_ptr() as _) as u64;

    let message_box_w_address = module_address + 0x72AD0;
    let message_box_w = *(&message_box_w_address as *const _ as *const MessageBoxW);
    let message_box_w_hook = MessageBoxWHook.initialize(message_box_w, hook_message_box_w).unwrap();
    message_box_w_hook.enable().unwrap();
}

unsafe extern "system" fn init_hook(_: LPVOID) -> u32 {
    detour_message_box_w();

    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(_: winapi::shared::minwindef::HINSTANCE, reason: u32, _: LPVOID) -> i32 {
    use winapi::um::processthreadsapi::CreateThread;

    match reason {
        1 => unsafe { CreateThread(null_mut(), 0, Some(init_hook), null_mut(), 0, null_mut()); }
        0 => (),
        _ => (),
    }

    1
}

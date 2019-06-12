extern crate libc;
extern crate winapi;

use std::ptr::{null, null_mut};
use winapi::shared::{
    minwindef::LPVOID,
    ntdef::LPCWSTR,
    windef::HWND,
};

type MessageBoxWHook = *const unsafe extern "system" fn(HWND, LPCWSTR, LPCWSTR, u32) -> i32;

static mut MESSAGE_BOX_W_HOOK_ADDRESS: u64 = 0;

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

unsafe extern "system" fn hook_message_box_w(h_wnd: HWND, _: LPCWSTR, _: LPCWSTR, u_type: u32) -> i32 {
    (*(&MESSAGE_BOX_W_HOOK_ADDRESS as *const _ as MessageBoxWHook))(
        h_wnd,
        "Ops hooked by Xavier!\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        "Ops hooked by Xavier!\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        u_type,
    )
}

unsafe fn detour(module_name: *const i8, old_func_offset: u64, new_func_address: u64) -> u64 {
    use std::mem::size_of;
    use libc::strcmp;
    use winapi::{
        um::{
            libloaderapi::GetModuleHandleA,
            memoryapi::VirtualProtect,
            winnt::{PAGE_EXECUTE_READWRITE, PIMAGE_DOS_HEADER, PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_NT_HEADERS},
            winuser::{MB_OK, MessageBoxA},
        },
    };

    let module_address = GetModuleHandleA(module_name) as u64;
    let old_func_address = module_address + old_func_offset;

    let image_base = GetModuleHandleA(null()) as u64;
    let p_dos_header = image_base as PIMAGE_DOS_HEADER;
    let p_nt_headers = (image_base + (*p_dos_header).e_lfanew as u64) as PIMAGE_NT_HEADERS;
    let mut p_import_descriptor = (image_base + (*p_nt_headers).OptionalHeader.DataDirectory[1].VirtualAddress as u64) as PIMAGE_IMPORT_DESCRIPTOR;

    while (*p_import_descriptor).FirstThunk != 0 {
//        MessageBoxA(null_mut(), (image_base + (*p_import_descriptor).Name as u64) as _, "\0".as_ptr() as _, MB_OK);
        if strcmp(module_name, (image_base + (*p_import_descriptor).Name as u64) as *const i8) != 0 {
            p_import_descriptor = p_import_descriptor.offset(1);
            continue;
        }
        MessageBoxA(null_mut(), (image_base + (*p_import_descriptor).Name as u64) as _, "\0".as_ptr() as _, MB_OK);

        let mut p_func = (image_base + (*p_import_descriptor).FirstThunk as u64) as *mut u64;
        for i in 0.. {
            if p_func.is_null() { return 0; }

//            MessageBoxA(null_mut(), (image_base + (*((image_base + *(*p_import_descriptor).u.OriginalFirstThunk() as u64) as *const u64).offset(i)) + 2) as _, "\0".as_ptr() as _, MB_OK);
            if old_func_address == *p_func {
                MessageBoxA(null_mut(), (image_base + (*((image_base + *(*p_import_descriptor).u.OriginalFirstThunk() as u64) as *const u64).offset(i)) + 2) as _, "\0".as_ptr() as _, MB_OK);

                let mut old_protection = 0u32;
                VirtualProtect(p_func as _, size_of::<LPVOID>(), PAGE_EXECUTE_READWRITE, &mut old_protection as _);
                *p_func = new_func_address;
                VirtualProtect(p_func as _, size_of::<LPVOID>(), old_protection, &mut old_protection as _);

                return old_func_address;
            }

            p_func = p_func.offset(1);
        }

        return 0;
    }

    0
}

unsafe extern "system" fn init_hook(_: LPVOID) -> u32 {
    MESSAGE_BOX_W_HOOK_ADDRESS = detour("USER32.dll\0".as_ptr() as _, 0x72AD0, hook_message_box_w as _);

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

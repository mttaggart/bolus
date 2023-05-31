mod injectors;
use injectors::{
    InjectorType,
    Injector
};

pub fn init(injector_type: InjectorType ) -> Box<dyn Injector> {

}
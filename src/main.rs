use std::{env, io};
use std::path::PathBuf;
use home;
use ssh_key::{HashAlg, PrivateKey};
use std::process::ExitCode;
mod shared;
use shared::{marked_string_to_vec, u82marked_string};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let private_key_path = if args.len() == 2 {
        PathBuf::from(args[1].clone())
    }else{
        let mut tmp = match home::home_dir() {
            Some(path) => path,
            _ => PathBuf::new()
        };

        tmp.push(".ssh/id_ed25519");
        tmp
    };

    if !private_key_path.is_file(){
        eprintln!("{} is not a file", private_key_path.to_string_lossy());
        return ExitCode::from(1)
    }

    let private_key = PrivateKey::read_openssh_file(&private_key_path).expect("Could not read private key");
    if ssh_key::Algorithm::Ed25519 != private_key.algorithm() {
        eprintln!("{} is not a Ed25519 private key", private_key_path.to_string_lossy());
        return ExitCode::from(2)
    };
    println!("Loaded {}, enter challenges", private_key_path.as_os_str().to_string_lossy());

    loop {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).expect("Could not read line");
        let entropy = match marked_string_to_vec(&buffer){
            Ok(t) => t,
            Err(e) => {
                println!("No valid challenge: {}", e);
                continue;
            }
        };

        let Ok(signature) = private_key.sign("pam-ed25519", HashAlg::Sha512, &*entropy) else {
            println!("Could not sign answer");
            continue;
        };

        let signature_bytes = signature.signature_bytes();
        
        println!("{}", u82marked_string(signature_bytes));
    }
}
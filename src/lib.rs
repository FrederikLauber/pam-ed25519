extern crate pam;

use std::ffi::CStr;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_ON};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;

use ssh_key::{HashAlg, PublicKey, SshSig};
use ssh_key::Signature;
mod shared;
use shared::{marked_string_to_vec, u82marked_string};

struct PamEd25519;
pam::pam_hooks!(PamEd25519);

pub fn get_home_of_user(username: &str) -> Option<PathBuf> {
    let file = File::open("/etc/passwd").ok()?;
    for line in BufReader::new(file).lines().flatten() {
        if line.starts_with(&format!("{}:", username)) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                return Some(PathBuf::from(parts[5].to_string())); // 6. field is home folder
            }
        }
    }
    None
}

macro_rules! result_or_abort {
    ($l:expr) => {match $l{
        Ok(e) => e,
        Err(_) => {
            return PamResultCode::PAM_ABORT;}
        }
    }
}

impl PamHooks  for PamEd25519 {
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode  {
        let user = match pam_try!(pamh.get_item::<pam::items::User>()) {
            Some(e) => e,
            None => {return PamResultCode::PAM_ABORT;}
        };

        let user_string = result_or_abort!(user.to_str());
        let mut path = match get_home_of_user(user_string){
            Some(t) => t,
            None => {
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        path.push(".ssh/id_ed25519.pub");
        let pub_key = result_or_abort!(PublicKey::read_openssh_file(&path));
        if ssh_key::Algorithm::Ed25519 != pub_key.algorithm() {
            return PamResultCode::PAM_AUTH_ERR;
        }

        let entropy: [u8; 32] = rand::random();
        let challenge = u82marked_string(&entropy);

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            _ => { return PamResultCode::PAM_ABORT; }
        };

        // First print the challenge visibly
        let _ = conv.send(pam::constants::PAM_TEXT_INFO, &format!("Challenge: {}\n", challenge));
        // Now prompt for the response
        let response = match pam_try!(conv.send(PAM_PROMPT_ECHO_ON, "Response: ")) {
            Some(response) => response,
            None => {
                return PamResultCode::PAM_AUTH_ERR;
            },
        };

        // read the return value and turn it back into bytes
        let response_str = result_or_abort!(response.to_str());
        let response_bytes = result_or_abort!(marked_string_to_vec(response_str));
        // build the signature object
        let signature: Signature = result_or_abort!(Signature::new(ssh_key::Algorithm::Ed25519, &response_bytes[..]));
        let sig = result_or_abort!(SshSig::new(pub_key.key_data().clone(), "pam-ed25519", HashAlg::Sha512, signature));

        // verify the signature
        if pub_key.verify("pam-ed25519", &entropy, &sig).is_ok(){
            PamResultCode::PAM_SUCCESS
        } else {
            PamResultCode::PAM_AUTH_ERR
        }
    }
}

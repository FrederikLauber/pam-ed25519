use regex::Regex;
use once_cell::sync::Lazy;

static MARKER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[^']*'*([^']+)'*").expect("Invalid regex")
});

pub fn u82marked_string(data: &[u8]) -> String {     
    format!("'''{}'''", base85::encode(&data))
}

pub fn marked_string_to_vec(data: &str) -> Result<Vec<u8>, &'static str> {
    let caps = MARKER_RE
        .captures(data)
        .ok_or("No match found")?;

    let encoded = caps.get(1).map(|m| m.as_str()).ok_or("Missing capture group")?;
    base85::decode(encoded).map_err(|_| "Base85 decoding failed")
}

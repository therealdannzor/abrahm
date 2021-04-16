use std::io::Write;

#[allow(dead_code)]
pub fn write_file<K: AsRef<[u8]>>(key: K, path: &str) -> std::io::Result<()> {
    // no matter where we are in the project folder, always save the keys in the same
    // directory as the cargo manifest
    let new_path = remove_suffix(&path, "/src");
    let mut file = std::fs::File::create(new_path)?;
    file.write_all(key.as_ref())?;
    Ok(())
}

pub fn remove_suffix<'a>(s: &'a &str, p: &str) -> &'a str {
    if s.ends_with(p) {
        &s[..s.len() - p.len()]
    } else {
        s
    }
}

#[allow(dead_code)]
pub fn remove_trail_chars(s: String) -> Option<String> {
    // check we have a full public key string
    if s.len() == 90 {
        // let the last 40 characters be the account address
        Some(s[50..].to_string())
    } else {
        None
    }
}

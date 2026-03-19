pub fn blob_url(public_base: &str, sha256: &str) -> String {
    format!("{}/{}", public_base.trim_end_matches('/'), sha256)
}

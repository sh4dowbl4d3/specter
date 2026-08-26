use crate::hash_id::{identify, HashType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub hash: String,
    pub plaintext: Option<String>,
    pub method: String,
}

pub fn crack_from_list(hash: &str, wordlist: &str) -> Option<CrackResult> {
    let trimmed_hash = hash.trim().to_lowercase();
    let ident = identify(hash);

    let mut hash_types: Vec<HashType> = if ident.is_empty() {
        vec![HashType::Unknown]
    } else {
        ident.iter().map(|i| i.hash_type.clone()).collect()
    };

    if trimmed_hash.len() == 32
        && trimmed_hash.chars().all(|c| c.is_ascii_hexdigit())
        && !hash_types.contains(&HashType::Ntlm)
    {
        hash_types.push(HashType::Ntlm);
    }

    // Trim once up front; the same words are tested against every hash type.
    let words: Vec<&str> = wordlist
        .lines()
        .map(|line| line.trim())
        .filter(|w| !w.is_empty())
        .collect();

    for ht in &hash_types {
        let hasher = match get_hasher(ht) {
            Some(h) => h,
            None => continue,
        };

        for word in words.iter().copied() {
            if hasher(word).eq_ignore_ascii_case(&trimmed_hash) {
                return Some(CrackResult {
                    hash: hash.to_string(),
                    plaintext: Some(word.to_string()),
                    method: format!("dictionary ({})", ht.name()),
                });
            }
        }
    }

    let method = ident
        .first()
        .map(|i| format!("dictionary ({})", i.hash_type.name()))
        .unwrap_or_else(|| "dictionary (unknown)".to_string());

    Some(CrackResult {
        hash: hash.to_string(),
        plaintext: None,
        method,
    })
}

fn get_hasher(ht: &HashType) -> Option<fn(&str) -> String> {
    match ht {
        HashType::Md5 => Some(hash_md5 as fn(&str) -> String),
        HashType::Sha1 => Some(hash_sha1 as fn(&str) -> String),
        HashType::Sha256 => Some(hash_sha256 as fn(&str) -> String),
        HashType::Sha224 => Some(hash_sha224 as fn(&str) -> String),
        HashType::Sha384 => Some(hash_sha384 as fn(&str) -> String),
        HashType::Sha512 => Some(hash_sha512 as fn(&str) -> String),
        HashType::Ntlm => Some(hash_ntlm as fn(&str) -> String),
        HashType::Mysql3 => Some(hash_mysql3 as fn(&str) -> String),
        HashType::Mysql41 => Some(hash_mysql41 as fn(&str) -> String),
        _ => None,
    }
}

pub fn hash_md5(s: &str) -> String {
    hash_md5_bytes(s.as_bytes())
}

pub fn hash_md5_bytes(bytes: &[u8]) -> String {
    format!("{:x}", md5::compute(bytes))
}

/// Raw (unhexed) digests for hot cracking paths — no per-candidate allocation.
pub(crate) mod raw {
    pub fn md5(bytes: &[u8]) -> [u8; 16] {
        md5::compute(bytes).0
    }

    pub fn sha1(bytes: &[u8]) -> [u8; 20] {
        use sha1::Digest;
        sha1::Sha1::digest(bytes).into()
    }

    pub fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(bytes).into()
    }
}

/// Compares the lowercase hex of `digest` with `target` without allocating.
pub(crate) fn hex_eq_ignore_case(digest: &[u8], target: &[u8]) -> bool {
    if digest.len() * 2 != target.len() {
        return false;
    }
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in digest.iter().enumerate() {
        if !HEX_LOWER[usize::from(b >> 4)].eq_ignore_ascii_case(&target[2 * i])
            || !HEX_LOWER[usize::from(b & 0x0f)].eq_ignore_ascii_case(&target[2 * i + 1])
        {
            return false;
        }
    }
    true
}

pub fn hash_sha1(s: &str) -> String {
    hash_sha1_bytes(s.as_bytes())
}

pub fn hash_sha1_bytes(bytes: &[u8]) -> String {
    use sha1::Digest;
    format!("{:x}", sha1::Sha1::digest(bytes))
}

pub fn hash_sha224(s: &str) -> String {
    hash_sha224_bytes(s.as_bytes())
}

pub fn hash_sha224_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha224::digest(bytes))
}

pub fn hash_sha256(s: &str) -> String {
    hash_sha256_bytes(s.as_bytes())
}

pub fn hash_sha256_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

pub fn hash_sha384(s: &str) -> String {
    hash_sha384_bytes(s.as_bytes())
}

pub fn hash_sha384_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha384::digest(bytes))
}

pub fn hash_sha512(s: &str) -> String {
    hash_sha512_bytes(s.as_bytes())
}

pub fn hash_sha512_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha512::digest(bytes))
}

pub fn hash_ntlm(s: &str) -> String {
    use md4::Digest;
    let encoded: Vec<u16> = s.encode_utf16().collect();
    let bytes: Vec<u8> = encoded.iter().flat_map(|c| c.to_le_bytes()).collect();
    let digest = md4::Md4::digest(&bytes);
    digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
        .to_uppercase()
}

pub fn hash_mysql3(s: &str) -> String {
    let mut nr = 1_345_345_333u64;
    let mut add = 7u64;
    let mut nr2 = 0x1234_5671u64;

    for byte in s.bytes().filter(|byte| *byte != b' ' && *byte != b'\t') {
        let value = byte as u64;
        nr ^= ((nr & 63).wrapping_add(add).wrapping_mul(value)).wrapping_add(nr << 8);
        nr2 = nr2.wrapping_add((nr2 << 8) ^ nr);
        add = add.wrapping_add(value);
    }

    format!("{:016X}", ((nr & 0x7fff_ffff) << 32) | (nr2 & 0x7fff_ffff))
}

pub fn hash_mysql41(s: &str) -> String {
    use sha1::Digest;
    let stage1 = sha1::Sha1::digest(s.as_bytes());
    let stage2 = sha1::Sha1::digest(stage1);
    format!("*{:X}", stage2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_hash() {
        assert_eq!(hash_ntlm("admin"), "209C6174DA490CAEB422F3FA5A7AE634");
    }

    #[test]
    fn test_md5_hash() {
        assert_eq!(hash_md5("password"), "5f4dcc3b5aa765d61d8327deb882cf99");
    }

    #[test]
    fn test_binary_hash_uses_original_bytes() {
        assert_eq!(
            hash_sha256_bytes(&[0, 159, 146, 150]),
            "b02a591131217cb579165aeccf0d94569acffb9934c84d6c813d77e3abedd233"
        );
    }

    #[test]
    fn test_sha256_hash() {
        assert_eq!(
            hash_sha256("admin"),
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
        );
    }

    #[test]
    fn test_crack_md5() {
        let wordlist = "password\nadmin\ntest\n";
        let result = crack_from_list("5f4dcc3b5aa765d61d8327deb882cf99", wordlist);
        assert!(result.is_some());
        assert_eq!(result.unwrap().plaintext.unwrap(), "password");
    }

    #[test]
    fn test_crack_ntlm() {
        let wordlist = "password\nadmin\ntest\n";
        let result = crack_from_list("209C6174DA490CAEB422F3FA5A7AE634", wordlist);
        assert!(result.is_some());
        assert_eq!(result.as_ref().unwrap().plaintext.as_deref(), Some("admin"));
    }

    #[test]
    fn test_crack_sha256() {
        let wordlist = "password\nadmin\ntest\n";
        let result = crack_from_list(
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
            wordlist,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().plaintext.unwrap(), "admin");
    }
}

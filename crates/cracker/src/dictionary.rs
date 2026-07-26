use hash_id::{identify, HashType};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub hash: String,
    pub plaintext: Option<String>,
    pub method: String,
}

pub fn crack_from_path(hash: &str, wordlist_path: &Path) -> Result<Option<CrackResult>, super::CrackerError> {
    let contents = std::fs::read_to_string(wordlist_path)?;
    Ok(crack_from_list(hash, &contents))
}

pub fn crack_from_list(hash: &str, wordlist: &str) -> Option<CrackResult> {
    let trimmed_hash = hash.trim().to_lowercase();
    let ident = identify(hash);
    let ht = ident
        .first()
        .map(|i| i.hash_type.clone())
        .unwrap_or(HashType::Unknown);

    let hasher = get_hasher(&ht);
    let hasher = match hasher {
        Some(h) => h,
        None => {
            return Some(CrackResult {
                hash: hash.to_string(),
                plaintext: None,
                method: format!("dictionary (unsupported: {})", ht.name()),
            });
        }
    };

    for line in wordlist.lines() {
        let word = line.trim();
        if word.is_empty() {
            continue;
        }
        if hasher(word).eq_ignore_ascii_case(&trimmed_hash) {
            return Some(CrackResult {
                hash: hash.to_string(),
                plaintext: Some(word.to_string()),
                method: format!("dictionary ({})", ht.name()),
            });
        }
    }

    Some(CrackResult {
        hash: hash.to_string(),
        plaintext: None,
        method: format!("dictionary ({})", ht.name()),
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
    format!("{:x}", md5::compute(s.as_bytes()))
}

pub fn hash_sha1(s: &str) -> String {
    use sha1::Digest;
    format!("{:x}", sha1::Sha1::digest(s.as_bytes()))
}

pub fn hash_sha224(s: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha224::digest(s.as_bytes()))
}

pub fn hash_sha256(s: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(s.as_bytes()))
}

pub fn hash_sha384(s: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha384::digest(s.as_bytes()))
}

pub fn hash_sha512(s: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha512::digest(s.as_bytes()))
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
    let mut hash = 0u64;
    for b in s.bytes() {
        hash = hash.wrapping_mul(7).wrapping_add(b as u64);
    }
    if hash == 0 {
        return "0".to_string();
    }
    format!("{:x}", hash).to_uppercase()
}

pub fn hash_mysql41(s: &str) -> String {
    use sha1::Digest;
    let stage1 = sha1::Sha1::digest(s.as_bytes());
    let stage1_hex = format!("{:x}", stage1).to_uppercase();
    let stage2 = sha1::Sha1::digest(stage1_hex.as_bytes());
    format!("*{:x}", stage2).to_uppercase()
}

use crate::dictionary::{hash_md5, hash_sha1, hash_sha256};
use hash_id::{identify, HashType};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

const CHARSET_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const CHARSET_LOWER_DIGIT: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const CHARSET_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    pub hash: String,
    pub max_length: u8,
    pub charset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceResult {
    pub cracked: bool,
    pub plaintext: Option<String>,
    pub attempts: u64,
    pub method: String,
}

pub fn brute_force_crack(config: &BruteForceConfig) -> BruteForceResult {
    let charset_bytes: &[u8] = match config.charset.as_str() {
        "lower" => CHARSET_LOWER,
        "lowerdigit" => CHARSET_LOWER_DIGIT,
        "alnum" => CHARSET_ALNUM,
        _ => CHARSET_LOWER_DIGIT,
    };

    let trimmed = config.hash.trim().to_lowercase();
    let ident = identify(&config.hash);
    let ht = ident
        .first()
        .map(|i| i.hash_type.clone())
        .unwrap_or(HashType::Unknown);

    if !is_brute_forceable(&trimmed, &ht) {
        return BruteForceResult {
            cracked: false,
            plaintext: None,
            attempts: 0,
            method: "brute-force (skipped - hash too long or unsupported)".to_string(),
        };
    }

    let hasher: fn(&str) -> String = match ht {
        HashType::Md5 => hash_md5,
        HashType::Sha1 => hash_sha1,
        HashType::Sha256 => hash_sha256,
        _ => {
            return BruteForceResult {
                cracked: false,
                plaintext: None,
                attempts: 0,
                method: "brute-force (unsupported hash type)".to_string(),
            }
        }
    };

    let mut total_attempts: u64 = 0;

    for len in 1..=config.max_length {
        let count = charset_bytes.len().pow(len as u32) as u64;
        if total_attempts + count > 20_000_000 {
            break;
        }

        let indices: Vec<Vec<usize>> = generate_all_indices(charset_bytes.len(), len as usize);

        let result = indices.par_iter().find_map_any(|seq| {
            let word: String = seq.iter().map(|&i| charset_bytes[i] as char).collect();
            let h = hasher(&word);
            if h.eq_ignore_ascii_case(&trimmed) {
                Some(word)
            } else {
                None
            }
        });

        total_attempts += count;

        if let Some(plaintext) = result {
            return BruteForceResult {
                cracked: true,
                plaintext: Some(plaintext),
                attempts: total_attempts,
                method: format!("brute-force (len={}, charset={})", len, config.charset),
            };
        }
    }

    BruteForceResult {
        cracked: false,
        plaintext: None,
        attempts: total_attempts,
        method: "brute-force (exhausted)".to_string(),
    }
}

fn generate_all_indices(alphabet_size: usize, len: usize) -> Vec<Vec<usize>> {
    let total = alphabet_size.pow(len as u32);
    (0..total)
        .map(|mut n| {
            let mut seq = Vec::with_capacity(len);
            for _ in 0..len {
                seq.push(n % alphabet_size);
                n /= alphabet_size;
            }
            seq.reverse();
            seq
        })
        .collect()
}

fn is_brute_forceable(hash: &str, ht: &HashType) -> bool {
    match ht {
        HashType::Md5 | HashType::Sha1 | HashType::Sha256 => hash.len() <= 64,
        _ => false,
    }
}

use crate::cracker::dictionary::{hash_md5, hash_sha1, hash_sha256};
use crate::hash_id::{identify, HashType};
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

const MAX_ATTEMPTS: u64 = 20_000_000;

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

    let mut total_attempts = 0u64;

    for len in 1..=usize::from(config.max_length) {
        let Some(candidate_count) = (charset_bytes.len() as u64).checked_pow(len as u32) else {
            break;
        };
        let budget = MAX_ATTEMPTS.saturating_sub(total_attempts);
        if budget == 0 {
            break;
        }
        let limit = candidate_count.min(budget);
        let mut indices = vec![0usize; len];

        for _ in 0..limit {
            let word: String = indices.iter().map(|&i| charset_bytes[i] as char).collect();
            total_attempts += 1;
            if hasher(&word).eq_ignore_ascii_case(&trimmed) {
                return BruteForceResult {
                    cracked: true,
                    plaintext: Some(word),
                    attempts: total_attempts,
                    method: format!("brute-force (len={}, charset={})", len, config.charset),
                };
            }
            if !increment_indices(&mut indices, charset_bytes.len()) {
                break;
            }
        }
    }

    BruteForceResult {
        cracked: false,
        plaintext: None,
        attempts: total_attempts,
        method: "brute-force (exhausted)".to_string(),
    }
}

fn increment_indices(indices: &mut [usize], alphabet_size: usize) -> bool {
    for index in indices.iter_mut().rev() {
        *index += 1;
        if *index < alphabet_size {
            return true;
        }
        *index = 0;
    }
    false
}

fn is_brute_forceable(hash: &str, ht: &HashType) -> bool {
    match ht {
        HashType::Md5 | HashType::Sha1 | HashType::Sha256 => hash.len() <= 64,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brute_force_md5_test() {
        let config = BruteForceConfig {
            hash: "098f6bcd4621d373cade4e832627b4f6".to_string(),
            max_length: 4,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(result.cracked);
        assert_eq!(result.plaintext.unwrap(), "test");
    }

    #[test]
    fn test_brute_force_md5_admin() {
        let config = BruteForceConfig {
            hash: "21232f297a57a5a743894a0e4a801fc3".to_string(),
            max_length: 5,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(result.cracked);
        assert_eq!(result.plaintext.unwrap(), "admin");
    }

    #[test]
    fn test_brute_force_not_found() {
        let config = BruteForceConfig {
            hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            max_length: 2,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(!result.cracked);
        assert_eq!(result.attempts, 702);
    }

    #[test]
    fn test_brute_force_unsupported_hash() {
        let config = BruteForceConfig {
            hash: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".to_string(),
            max_length: 2,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(!result.cracked);
        assert_eq!(
            result.method,
            "brute-force (skipped - hash too long or unsupported)"
        );
    }
}

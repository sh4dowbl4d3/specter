use crate::cipher_tools::error::CipherError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CipherType {
    Caesar,
    Rot13,
    Atbash,
    Base64,
    Hex,
    Binary,
    Vigenere,
    Unknown,
}

impl CipherType {
    pub fn name(&self) -> &str {
        match self {
            CipherType::Caesar => "Caesar",
            CipherType::Rot13 => "ROT13",
            CipherType::Atbash => "Atbash",
            CipherType::Base64 => "Base64",
            CipherType::Hex => "Hex",
            CipherType::Binary => "Binary",
            CipherType::Vigenere => "Vigenère",
            CipherType::Unknown => "Unknown",
        }
    }
}

pub fn caesar_decrypt(input: &str, shift: u8) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shifted = (c as u8 - first + 26 - (shift % 26)) % 26 + first;
                shifted as char
            } else {
                c
            }
        })
        .collect()
}

pub fn caesar_encrypt(input: &str, shift: u8) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shifted = (c as u8 - first + (shift % 26)) % 26 + first;
                shifted as char
            } else {
                c
            }
        })
        .collect()
}

pub fn caesar_bruteforce(input: &str) -> Vec<(u8, String)> {
    (0..26).map(|s| (s, caesar_decrypt(input, s))).collect()
}

pub fn rot13(input: &str) -> String {
    caesar_decrypt(input, 13)
}

pub fn atbash(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let last = if c.is_ascii_lowercase() { b'z' } else { b'Z' };
                (last - (c as u8 - first)) as char
            } else {
                c
            }
        })
        .collect()
}

pub fn base64_decode(input: &str) -> Result<String, CipherError> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine
        .decode(input.trim())
        .map_err(|e| CipherError::Decode(format!("Base64: {}", e)))?;
    String::from_utf8(bytes).map_err(|e| CipherError::Decode(format!("UTF-8: {}", e)))
}

pub fn base64_encode(input: &str) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(input.as_bytes())
}

pub fn hex_decode(input: &str) -> Result<String, CipherError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned).map_err(|e| CipherError::Decode(format!("Hex: {}", e)))?;
    String::from_utf8(bytes).map_err(|e| CipherError::Decode(format!("UTF-8: {}", e)))
}

pub fn hex_encode(input: &str) -> String {
    hex::encode(input.as_bytes())
}

pub fn binary_decode(input: &str) -> Result<String, CipherError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(8) {
        return Err(CipherError::Decode(
            "Binary: length not multiple of 8".to_string(),
        ));
    }
    if !cleaned.bytes().all(|b| b == b'0' || b == b'1') {
        return Err(CipherError::Decode(
            "Binary: only 0 and 1 are valid".to_string(),
        ));
    }
    let bytes: Vec<u8> = cleaned
        .as_bytes()
        .chunks(8)
        .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | (b - b'0')))
        .collect();
    String::from_utf8(bytes).map_err(|e| CipherError::Decode(format!("UTF-8: {}", e)))
}

pub fn binary_encode(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn vigenere_decrypt(input: &str, key: &str) -> String {
    if key.is_empty() {
        return input.to_string();
    }
    let key_lower: Vec<u8> = key
        .bytes()
        .filter(|byte| byte.is_ascii_alphabetic())
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    if key_lower.is_empty() {
        return input.to_string();
    }
    let key_len = key_lower.len();
    let mut key_idx = 0;

    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shift = key_lower[key_idx % key_len] - b'a';
                key_idx += 1;
                let shifted = (c as u8 - first + 26 - shift) % 26 + first;
                shifted as char
            } else {
                c
            }
        })
        .collect()
}

pub fn vigenere_encrypt(input: &str, key: &str) -> String {
    if key.is_empty() {
        return input.to_string();
    }
    let key_lower: Vec<u8> = key
        .bytes()
        .filter(|byte| byte.is_ascii_alphabetic())
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    if key_lower.is_empty() {
        return input.to_string();
    }
    let key_len = key_lower.len();
    let mut key_idx = 0;

    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shift = key_lower[key_idx % key_len] - b'a';
                key_idx += 1;
                let shifted = (c as u8 - first + shift) % 26 + first;
                shifted as char
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caesar_decrypt() {
        assert_eq!(caesar_decrypt("khoor", 3), "hello");
    }

    #[test]
    fn test_caesar_encrypt() {
        assert_eq!(caesar_encrypt("hello", 3), "khoor");
    }

    #[test]
    fn test_rot13() {
        assert_eq!(rot13("uryyb"), "hello");
    }

    #[test]
    fn test_atbash() {
        assert_eq!(atbash("svool"), "hello");
    }

    #[test]
    fn test_base64_roundtrip() {
        let encoded = base64_encode("hello world");
        assert_eq!(base64_decode(&encoded).unwrap(), "hello world");
    }

    #[test]
    fn test_hex_roundtrip() {
        let encoded = hex_encode("hello");
        assert_eq!(hex_decode(&encoded).unwrap(), "hello");
    }

    #[test]
    fn test_binary_roundtrip() {
        let encoded = binary_encode("hello");
        assert_eq!(binary_decode(&encoded).unwrap(), "hello");
    }

    #[test]
    fn test_vigenere_invalid_key_is_safe() {
        assert_eq!(vigenere_encrypt("hello", "123!"), "hello");
        assert_eq!(vigenere_decrypt("hello", "é"), "hello");
    }

    #[test]
    fn test_vigenere_roundtrip() {
        let encrypted = vigenere_encrypt("hello", "key");
        assert_eq!(vigenere_decrypt(&encrypted, "key"), "hello");
    }

    #[test]
    fn test_caesar_bruteforce() {
        let results = caesar_bruteforce("khoor");
        assert!(results.iter().any(|(_, s)| s == "hello"));
    }

    #[test]
    fn test_binary_decode_rejects_non_binary() {
        // from_str_radix used to accept signs and other radix-2 oddities here.
        assert!(binary_decode("1010-0101").is_err());
        assert!(binary_decode("+0001101").is_err());
        assert!(binary_decode("abcdefgh").is_err());
    }

    #[test]
    fn test_binary_decode_boundary_values() {
        assert_eq!(binary_decode("01111111").unwrap(), "\u{7f}");
        // A lone 0xFF byte is not valid UTF-8, so decoding must fail cleanly.
        assert!(binary_decode("11111111").is_err());
    }

    #[test]
    fn test_base64_decode_invalid_input_errors() {
        assert!(base64_decode("!!!!").is_err());
        assert!(base64_decode("abc").is_err()); // not a multiple of 4
    }

    #[test]
    fn test_hex_decode_odd_length_errors() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn test_hex_decode_rejects_non_hex() {
        assert!(hex_decode("zzzz").is_err());
    }
}

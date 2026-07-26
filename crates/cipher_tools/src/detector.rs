use crate::ciphers::{
    atbash, base64_decode, binary_decode, caesar_decrypt, hex_decode, rot13, CipherType,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherDetection {
    pub cipher_type: CipherType,
    pub confidence: f64,
    pub decoded: Option<String>,
}

pub fn detect_cipher(input: &str) -> Vec<CipherDetection> {
    let trimmed = input.trim();
    let mut results = Vec::new();

    if trimmed.is_empty() {
        return results;
    }

    if is_likely_base64(trimmed) {
        if let Ok(decoded) = base64_decode(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::Base64,
                    confidence: 0.9,
                    decoded: Some(decoded),
                });
            }
        }
    }

    if is_likely_hex(trimmed) {
        if let Ok(decoded) = hex_decode(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::Hex,
                    confidence: 0.85,
                    decoded: Some(decoded),
                });
            }
        }
    }

    if is_likely_binary(trimmed) {
        if let Ok(decoded) = binary_decode(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::Binary,
                    confidence: 0.85,
                    decoded: Some(decoded),
                });
            }
        }
    }

    if is_likely_rot13(trimmed) {
        let decoded = rot13(trimmed);
        if is_readable_text(&decoded) && decoded != trimmed {
            results.push(CipherDetection {
                cipher_type: CipherType::Rot13,
                confidence: 0.7,
                decoded: Some(decoded),
            });
        }
    }

    let atbash_decoded = atbash(trimmed);
    if is_readable_text(&atbash_decoded) && atbash_decoded != trimmed {
        results.push(CipherDetection {
            cipher_type: CipherType::Atbash,
            confidence: 0.5,
            decoded: Some(atbash_decoded),
        });
    }

    let shift_results: Vec<(u8, String)> = (1..26)
        .map(|s| (s, caesar_decrypt(trimmed, s)))
        .filter(|(_, d)| is_readable_text(d))
        .collect();

    for (_shift, decoded) in shift_results.iter().take(3) {
        if *decoded != trimmed {
            results.push(CipherDetection {
                cipher_type: CipherType::Caesar,
                confidence: 0.5,
                decoded: Some(decoded.clone()),
            });
        }
    }

    results
}

fn is_likely_base64(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let valid_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !valid_chars {
        return false;
    }
    s.len() % 4 == 0 && s.chars().filter(|&c| c == '=').count() <= 2
}

fn is_likely_hex(s: &str) -> bool {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 2 || cleaned.len() % 2 != 0 {
        return false;
    }
    cleaned.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_likely_binary(s: &str) -> bool {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 8 || cleaned.len() % 8 != 0 {
        return false;
    }
    cleaned.chars().all(|c| c == '0' || c == '1')
}

fn is_likely_rot13(s: &str) -> bool {
    let alpha_count = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if alpha_count < 4 {
        return false;
    }
    let rot13_encoded = rot13(s);
    let common_letters = b"etaoinshrdlu";
    let orig_common = s
        .to_ascii_lowercase()
        .chars()
        .filter(|c| common_letters.contains(&(*c as u8)))
        .count();
    let rot13_common = rot13_encoded
        .to_ascii_lowercase()
        .chars()
        .filter(|c| common_letters.contains(&(*c as u8)))
        .count();
    rot13_common > orig_common
}

fn is_readable_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    let ratio = printable as f64 / s.len() as f64;
    ratio > 0.85 && s.len() > 2
}

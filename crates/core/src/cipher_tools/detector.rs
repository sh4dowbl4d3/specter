use crate::cipher_tools::ciphers::{
    atbash, bacon_decode, base64_decode, binary_decode, caesar_decrypt, decimal_to_ascii,
    hex_decode, morse_decode, reverse_text, rot13, url_decode, CipherType,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherDetection {
    pub cipher_type: CipherType,
    pub confidence: f64,
    pub decoded: Option<String>,
    pub explanation: String,
    pub ambiguity_warning: Option<String>,
}

pub fn detect_cipher(input: &str) -> Vec<CipherDetection> {
    let trimmed = input.trim();
    let mut results = Vec::new();

    if trimmed.is_empty() {
        return results;
    }

    let is_short = trimmed.len() <= 6;
    let ambiguity = if is_short {
        Some("Input is short and may match multiple classical or encoding formats".to_string())
    } else {
        None
    };

    if is_likely_morse(trimmed) {
        if let Ok(decoded) = morse_decode(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::Morse,
                    confidence: 0.95,
                    decoded: Some(decoded),
                    explanation: "International Morse code sequence (dots, dashes and slashes)"
                        .to_string(),
                    ambiguity_warning: None,
                });
            }
        }
    }

    if is_likely_binary(trimmed) {
        if let Ok(decoded) = binary_decode(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::Binary,
                    confidence: 0.92,
                    decoded: Some(decoded),
                    explanation: "8-bit binary ASCII byte stream".to_string(),
                    ambiguity_warning: None,
                });
            }
        }
    }

    if is_likely_bacon(trimmed) {
        if let Ok(decoded) = bacon_decode(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::Bacon,
                    confidence: 0.88,
                    decoded: Some(decoded),
                    explanation: "5-bit Francis Bacon steganographic cipher".to_string(),
                    ambiguity_warning: ambiguity.clone(),
                });
            }
        }
    }

    if is_likely_url(trimmed) {
        if let Ok(decoded) = url_decode(trimmed) {
            if is_readable_text(&decoded) && decoded != trimmed {
                results.push(CipherDetection {
                    cipher_type: CipherType::Url,
                    confidence: 0.88,
                    decoded: Some(decoded),
                    explanation: "Percent-encoded URL component".to_string(),
                    ambiguity_warning: ambiguity.clone(),
                });
            }
        }
    }

    if is_likely_hex(trimmed) {
        if let Ok(decoded) = hex_decode(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::Hex,
                    confidence: 0.86,
                    decoded: Some(decoded),
                    explanation: "Hexadecimal byte encoding".to_string(),
                    ambiguity_warning: ambiguity.clone(),
                });
            }
        }
    }

    if is_likely_decimal(trimmed) {
        if let Ok(decoded) = decimal_to_ascii(trimmed) {
            if is_readable_text(&decoded) {
                results.push(CipherDetection {
                    cipher_type: CipherType::AsciiDecimal,
                    confidence: 0.85,
                    decoded: Some(decoded),
                    explanation: "Space/comma-separated decimal ASCII byte values".to_string(),
                    ambiguity_warning: None,
                });
            }
        }
    }

    if is_likely_base64(trimmed) {
        if let Ok(decoded) = base64_decode(trimmed) {
            if is_readable_text(&decoded) {
                let conf = if trimmed.ends_with('=') { 0.90 } else { 0.82 };
                results.push(CipherDetection {
                    cipher_type: CipherType::Base64,
                    confidence: conf,
                    decoded: Some(decoded),
                    explanation: "Base64 RFC 4648 ASCII representation".to_string(),
                    ambiguity_warning: ambiguity.clone(),
                });
            }
        }
    }

    if is_likely_rot13(trimmed) {
        let decoded = rot13(trimmed);
        if is_readable_text(&decoded) && decoded != trimmed {
            results.push(CipherDetection {
                cipher_type: CipherType::Rot13,
                confidence: 0.75,
                decoded: Some(decoded),
                explanation: "ROT13 alphabet shift with characteristic English letter frequency"
                    .to_string(),
                ambiguity_warning: ambiguity.clone(),
            });
        }
    }

    let atbash_decoded = atbash(trimmed);
    if is_readable_text(&atbash_decoded) && atbash_decoded != trimmed {
        results.push(CipherDetection {
            cipher_type: CipherType::Atbash,
            confidence: 0.65,
            decoded: Some(atbash_decoded),
            explanation: "Atbash reciprocal alphabet cipher (A<->Z, B<->Y)".to_string(),
            ambiguity_warning: ambiguity.clone(),
        });
    }

    let reversed = reverse_text(trimmed);
    if is_readable_text(&reversed) && reversed != trimmed && !is_all_digits(trimmed) {
        results.push(CipherDetection {
            cipher_type: CipherType::Reverse,
            confidence: 0.55,
            decoded: Some(reversed),
            explanation: "Reversed text character order".to_string(),
            ambiguity_warning: ambiguity.clone(),
        });
    }

    // Shift 13 is reported as ROT13 above; skip it here to avoid duplicates.
    let shift_results: Vec<(u8, String)> = (1..26)
        .filter(|&s| s != 13)
        .map(|s| (s, caesar_decrypt(trimmed, s)))
        .filter(|(_, d)| is_readable_text(d))
        .collect();

    for (shift, decoded) in shift_results.iter().take(3) {
        if *decoded != trimmed {
            results.push(CipherDetection {
                cipher_type: CipherType::Caesar,
                confidence: 0.50,
                decoded: Some(decoded.clone()),
                explanation: format!("Caesar substitution with shift {shift}"),
                ambiguity_warning: ambiguity.clone(),
            });
        }
    }

    let total_candidates = results.len();
    if total_candidates > 2 {
        for r in &mut results {
            if r.ambiguity_warning.is_none() {
                r.ambiguity_warning = Some(format!(
                    "Multiple possible decodings detected ({total_candidates} candidates ranked by confidence)"
                ));
            }
        }
    }

    // Sort ranked candidates by confidence descending
    results.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    results
}

fn is_likely_morse(s: &str) -> bool {
    let non_ws: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    if non_ws.is_empty() {
        return false;
    }
    non_ws
        .iter()
        .all(|&c| c == '.' || c == '-' || c == '/' || c == '_')
        && non_ws.iter().any(|&c| c == '.' || c == '-')
}

fn is_likely_bacon(s: &str) -> bool {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '/')
        .collect();
    if clean.len() < 5 || !clean.len().is_multiple_of(5) {
        return false;
    }
    clean
        .chars()
        .all(|c| c == 'A' || c == 'B' || c == 'a' || c == 'b' || c == '0' || c == '1')
}

fn is_likely_url(s: &str) -> bool {
    s.contains('%')
        && s.len() >= 3
        && s.as_bytes().windows(3).any(|w| {
            w[0] == b'%' && (w[1] as char).is_ascii_hexdigit() && (w[2] as char).is_ascii_hexdigit()
        })
}

fn is_likely_decimal(s: &str) -> bool {
    let tokens: Vec<&str> = s
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() < 2 {
        return false;
    }
    tokens
        .iter()
        .all(|t| t.chars().all(|c| c.is_ascii_digit()) && t.parse::<u8>().is_ok())
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
    s.len().is_multiple_of(4) && s.chars().filter(|&c| c == '=').count() <= 2
}

fn is_likely_hex(s: &str) -> bool {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 2 || !cleaned.len().is_multiple_of(2) {
        return false;
    }
    cleaned.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_likely_binary(s: &str) -> bool {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 8 || !cleaned.len().is_multiple_of(8) {
        return false;
    }
    cleaned.chars().all(|c| c == '0' || c == '1')
}

fn is_all_digits(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit() || c.is_whitespace())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_base64() {
        let results = detect_cipher("aGVsbG8=");
        assert!(results.iter().any(|r| r.cipher_type == CipherType::Base64));
    }

    #[test]
    fn test_detect_hex() {
        let results = detect_cipher("68656c6c6f");
        assert!(results.iter().any(|r| r.cipher_type == CipherType::Hex));
    }

    #[test]
    fn test_detect_binary() {
        let results = detect_cipher("01101000 01100101 01101100 01101100 01101111");
        assert!(results.iter().any(|r| r.cipher_type == CipherType::Binary));
    }

    #[test]
    fn test_detect_rot13() {
        let results = detect_cipher("uryyb");
        assert!(results.iter().any(|r| r.cipher_type == CipherType::Rot13));
    }

    #[test]
    fn test_detect_morse() {
        let results = detect_cipher(".... . .-.. .-.. --- / .-- --- .-. .-.. -..");
        assert!(results.iter().any(|r| r.cipher_type == CipherType::Morse));
    }

    #[test]
    fn test_detect_url() {
        let results = detect_cipher("Hello%20World%21");
        assert!(results.iter().any(|r| r.cipher_type == CipherType::Url));
    }

    #[test]
    fn test_detect_decimal() {
        let results = detect_cipher("72 101 108 108 111");
        assert!(results
            .iter()
            .any(|r| r.cipher_type == CipherType::AsciiDecimal));
    }

    #[test]
    fn test_detect_bacon() {
        let results = detect_cipher("AABBB AABAA ABABB ABABB ABBBA");
        assert!(results.iter().any(|r| r.cipher_type == CipherType::Bacon));
    }

    #[test]
    fn test_detect_empty() {
        let results = detect_cipher("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_detect_whitespace_only_is_empty() {
        let results = detect_cipher("   \n\t  ");
        assert!(results.is_empty());
    }

    #[test]
    fn test_detect_rot13_not_duplicated_as_caesar() {
        let results = detect_cipher("uryyb jbeyq");
        assert_eq!(
            results
                .iter()
                .filter(|r| r.decoded.as_deref() == Some("hello world"))
                .count(),
            1
        );
    }
}

use crate::cipher_tools::error::CipherError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CipherType {
    Caesar,
    Rot13,
    Atbash,
    Base64,
    Hex,
    Binary,
    Vigenere,
    Url,
    AsciiDecimal,
    Morse,
    Reverse,
    RailFence,
    Affine,
    Bacon,
    Xor,
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
            CipherType::Url => "URL Encoding",
            CipherType::AsciiDecimal => "ASCII / Decimal",
            CipherType::Morse => "Morse Code",
            CipherType::Reverse => "Reverse Text",
            CipherType::RailFence => "Rail Fence",
            CipherType::Affine => "Affine",
            CipherType::Bacon => "Bacon's Cipher",
            CipherType::Xor => "XOR",
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

pub fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'.' || *b == b'~' {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn url_decode(input: &str) -> Result<String, CipherError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(CipherError::Decode("URL: incomplete percent-encoding".to_string()));
                }
                let h1 = bytes[i + 1];
                let h2 = bytes[i + 2];
                if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                    return Err(CipherError::Decode(
                        "URL: invalid hex digits in percent-encoding".to_string(),
                    ));
                }
                let val1 = match h1 {
                    b'0'..=b'9' => h1 - b'0',
                    b'a'..=b'f' => h1 - b'a' + 10,
                    b'A'..=b'F' => h1 - b'A' + 10,
                    _ => unreachable!(),
                };
                let val2 = match h2 {
                    b'0'..=b'9' => h2 - b'0',
                    b'a'..=b'f' => h2 - b'a' + 10,
                    b'A'..=b'F' => h2 - b'A' + 10,
                    _ => unreachable!(),
                };
                out.push((val1 << 4) | val2);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| CipherError::Decode(format!("UTF-8: {}", e)))
}

pub fn ascii_to_decimal(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn decimal_to_ascii(input: &str) -> Result<String, CipherError> {
    let tokens = input
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let mut bytes = Vec::new();
    for token in tokens {
        let val = token.parse::<u8>().map_err(|_| {
            CipherError::Decode(format!("Decimal: '{token}' is not a valid byte (0-255)"))
        })?;
        bytes.push(val);
    }
    String::from_utf8(bytes).map_err(|e| CipherError::Decode(format!("UTF-8: {}", e)))
}

const MORSE_TABLE: &[(char, &str)] = &[
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    ('.', ".-.-.-"),
    (',', "--..--"),
    ('?', "..--.."),
    ('\'', ".----."),
    ('!', "-.-.--"),
    ('/', "-..-."),
    ('(', "-.--."),
    (')', "-.--.-"),
    ('&', ".-..."),
    (':', "---..."),
    (';', "-.-.-."),
    ('=', "-...-"),
    ('+', ".-.-."),
    ('-', "-....-"),
    ('_', "..--.-"),
    ('"', ".-..-."),
    ('$', "...-..-"),
    ('@', ".--.-."),
];

pub fn morse_encode(input: &str) -> String {
    let mut words_out = Vec::new();
    for word in input.split_whitespace() {
        let mut letters_out = Vec::new();
        for c in word.chars() {
            let upper = c.to_ascii_uppercase();
            if let Some((_, code)) = MORSE_TABLE.iter().find(|(ch, _)| *ch == upper) {
                letters_out.push(*code);
            }
        }
        if !letters_out.is_empty() {
            words_out.push(letters_out.join(" "));
        }
    }
    words_out.join(" / ")
}

pub fn morse_decode(input: &str) -> Result<String, CipherError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    let words = trimmed.split('/');
    let mut decoded_words = Vec::new();

    for word in words {
        let tokens = word.split_whitespace();
        let mut word_str = String::new();
        for token in tokens {
            if token.is_empty() {
                continue;
            }
            if let Some((ch, _)) = MORSE_TABLE.iter().find(|(_, code)| *code == token) {
                word_str.push(*ch);
            } else {
                return Err(CipherError::Decode(format!(
                    "Morse: unknown sequence '{token}'"
                )));
            }
        }
        if !word_str.is_empty() {
            decoded_words.push(word_str);
        }
    }

    Ok(decoded_words.join(" "))
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

    #[test]
    fn test_url_roundtrip() {
        let text = "Hello World! @#$&*()+=:;,/?";
        let encoded = url_encode(text);
        assert_eq!(url_decode(&encoded).unwrap(), text);
    }

    #[test]
    fn test_url_decode_plus_as_space() {
        assert_eq!(url_decode("hello+world").unwrap(), "hello world");
    }

    #[test]
    fn test_url_decode_invalid_percent() {
        assert!(url_decode("%2").is_err());
        assert!(url_decode("%2G").is_err());
    }

    #[test]
    fn test_ascii_decimal_roundtrip() {
        let text = "Hello, World! 123";
        let encoded = ascii_to_decimal(text);
        assert_eq!(decimal_to_ascii(&encoded).unwrap(), text);
    }

    #[test]
    fn test_decimal_to_ascii_delimiters() {
        assert_eq!(decimal_to_ascii("72, 101, 108, 108, 111").unwrap(), "Hello");
        assert_eq!(decimal_to_ascii("72 101\n108\t108 111").unwrap(), "Hello");
    }

    #[test]
    fn test_decimal_to_ascii_invalid() {
        assert!(decimal_to_ascii("72 999").is_err());
        assert!(decimal_to_ascii("72 abc").is_err());
    }

    #[test]
    fn test_morse_roundtrip() {
        let text = "HELLO WORLD";
        let encoded = morse_encode(text);
        assert_eq!(encoded, ".... . .-.. .-.. --- / .-- --- .-. .-.. -..");
        assert_eq!(morse_decode(&encoded).unwrap(), text);
    }

    #[test]
    fn test_morse_decode_invalid() {
        assert!(morse_decode("........").is_err());
    }
}

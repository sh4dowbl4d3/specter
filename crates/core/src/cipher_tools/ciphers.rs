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
                    return Err(CipherError::Decode(
                        "URL: incomplete percent-encoding".to_string(),
                    ));
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

pub fn reverse_text(input: &str) -> String {
    input.chars().rev().collect()
}

pub fn reverse_words(input: &str) -> String {
    input
        .lines()
        .map(|line| line.split_whitespace().rev().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn rail_fence_encrypt(input: &str, rails: usize) -> Result<String, CipherError> {
    if rails < 2 {
        return Err(CipherError::InvalidKey(
            "Rail fence cipher requires at least 2 rails".to_string(),
        ));
    }
    let chars: Vec<char> = input.chars().collect();
    if chars.len() <= rails || chars.is_empty() {
        return Ok(input.to_string());
    }

    let mut fence: Vec<Vec<char>> = vec![Vec::new(); rails];
    let mut rail = 0;
    let mut going_down = true;

    for &c in &chars {
        fence[rail].push(c);
        if rail == 0 {
            going_down = true;
        } else if rail == rails - 1 {
            going_down = false;
        }
        if going_down {
            rail += 1;
        } else {
            rail -= 1;
        }
    }

    let mut result = String::with_capacity(chars.len());
    for row in fence {
        for c in row {
            result.push(c);
        }
    }
    Ok(result)
}

pub fn rail_fence_decrypt(input: &str, rails: usize) -> Result<String, CipherError> {
    if rails < 2 {
        return Err(CipherError::InvalidKey(
            "Rail fence cipher requires at least 2 rails".to_string(),
        ));
    }
    let chars: Vec<char> = input.chars().collect();
    let n = chars.len();
    if n <= rails || n == 0 {
        return Ok(input.to_string());
    }

    // Determine row pattern for each position
    let mut rail_for_pos = Vec::with_capacity(n);
    let mut rail = 0;
    let mut going_down = true;
    for _ in 0..n {
        rail_for_pos.push(rail);
        if rail == 0 {
            going_down = true;
        } else if rail == rails - 1 {
            going_down = false;
        }
        if going_down {
            rail += 1;
        } else {
            rail -= 1;
        }
    }

    // Count characters per rail
    let mut rail_counts = vec![0; rails];
    for &r in &rail_for_pos {
        rail_counts[r] += 1;
    }

    // Populate each rail with its slice of ciphertext characters
    let mut rail_chars: Vec<Vec<char>> = Vec::with_capacity(rails);
    let mut char_idx = 0;
    for count in rail_counts {
        rail_chars.push(chars[char_idx..char_idx + count].to_vec());
        char_idx += count;
    }

    // Read back in zigzag order
    let mut rail_ptr = vec![0; rails];
    let mut result = String::with_capacity(n);
    for r in rail_for_pos {
        let c = rail_chars[r][rail_ptr[r]];
        rail_ptr[r] += 1;
        result.push(c);
    }

    Ok(result)
}

fn mod_inverse_26(a: u8) -> Option<u8> {
    let a = (a % 26) as u16;
    if a == 0 {
        return None;
    }
    (1..26u16).find(|&x| (a * x) % 26 == 1).map(|x| x as u8)
}

pub fn affine_encrypt(input: &str, a: u8, b: u8) -> Result<String, CipherError> {
    let a = a % 26;
    let b = b % 26;
    if mod_inverse_26(a).is_none() {
        return Err(CipherError::InvalidKey(format!(
            "Affine 'a' parameter ({a}) must be coprime to 26"
        )));
    }

    let res = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let x = (c as u16) - (first as u16);
                let enc = ((a as u16) * x + (b as u16)) % 26 + (first as u16);
                (enc as u8) as char
            } else {
                c
            }
        })
        .collect();
    Ok(res)
}

pub fn affine_decrypt(input: &str, a: u8, b: u8) -> Result<String, CipherError> {
    let a = a % 26;
    let b = b % 26;
    let inv_a = mod_inverse_26(a).ok_or_else(|| {
        CipherError::InvalidKey(format!("Affine 'a' parameter ({a}) must be coprime to 26"))
    })? as u16;

    let res = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let y = (c as u16) - (first as u16);
                let dec = (inv_a * (y + 26 - (b as u16))) % 26 + (first as u16);
                (dec as u8) as char
            } else {
                c
            }
        })
        .collect();
    Ok(res)
}

pub fn bacon_encode(input: &str) -> String {
    let mut words_out = Vec::new();
    for word in input.split_whitespace() {
        let mut letters_out = Vec::new();
        for c in word.chars() {
            if c.is_ascii_alphabetic() {
                let idx = c.to_ascii_uppercase() as u8 - b'A';
                if idx < 26 {
                    let mut code = String::with_capacity(5);
                    for shift in (0..5).rev() {
                        if ((idx >> shift) & 1) == 1 {
                            code.push('B');
                        } else {
                            code.push('A');
                        }
                    }
                    letters_out.push(code);
                }
            }
        }
        if !letters_out.is_empty() {
            words_out.push(letters_out.join(" "));
        }
    }
    words_out.join(" / ")
}

pub fn bacon_decode(input: &str) -> Result<String, CipherError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    let words = trimmed.split('/');
    let mut decoded_words = Vec::new();

    for word in words {
        let tokens: Vec<String> = word
            .split_whitespace()
            .flat_map(|token| {
                let cleaned: String = token
                    .chars()
                    .filter(|c| c.is_ascii_alphabetic() || *c == '0' || *c == '1')
                    .collect();
                if cleaned.len() > 5 && cleaned.len().is_multiple_of(5) {
                    cleaned
                        .as_bytes()
                        .chunks(5)
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect::<Vec<_>>()
                } else {
                    vec![cleaned]
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        let mut word_str = String::new();
        for token in tokens {
            if token.len() != 5 {
                return Err(CipherError::Decode(format!(
                    "Bacon: block '{token}' must be exactly 5 characters"
                )));
            }
            let mut val = 0u8;
            for c in token.chars() {
                val <<= 1;
                match c.to_ascii_uppercase() {
                    'A' | '0' => {}
                    'B' | '1' => val |= 1,
                    _ => {
                        return Err(CipherError::Decode(format!(
                            "Bacon: invalid character '{c}' in block '{token}'"
                        )))
                    }
                }
            }
            if val < 26 {
                word_str.push((b'A' + val) as char);
            } else {
                return Err(CipherError::Decode(format!(
                    "Bacon: value {val} in block '{token}' out of range (0-25)"
                )));
            }
        }
        if !word_str.is_empty() {
            decoded_words.push(word_str);
        }
    }

    Ok(decoded_words.join(" "))
}

pub fn xor_bytes(input: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherError> {
    if key.is_empty() {
        return Err(CipherError::InvalidKey(
            "XOR key cannot be empty".to_string(),
        ));
    }
    Ok(input
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect())
}

pub fn xor_text_to_hex(input: &str, key: &str) -> Result<String, CipherError> {
    if key.is_empty() {
        return Err(CipherError::InvalidKey(
            "XOR key cannot be empty".to_string(),
        ));
    }
    let res = xor_bytes(input.as_bytes(), key.as_bytes())?;
    Ok(hex::encode(res))
}

pub fn xor_hex_to_text(hex_input: &str, key: &str) -> Result<String, CipherError> {
    if key.is_empty() {
        return Err(CipherError::InvalidKey(
            "XOR key cannot be empty".to_string(),
        ));
    }
    let cleaned: String = hex_input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned)
        .map_err(|e| CipherError::Decode(format!("Hex decode error in XOR: {e}")))?;
    let res = xor_bytes(&bytes, key.as_bytes())?;
    String::from_utf8(res).map_err(|e| CipherError::Decode(format!("UTF-8: {e}")))
}

pub fn xor_hex_with_hex(hex_input: &str, hex_key: &str) -> Result<String, CipherError> {
    let clean_in: String = hex_input.chars().filter(|c| !c.is_whitespace()).collect();
    let clean_key: String = hex_key.chars().filter(|c| !c.is_whitespace()).collect();
    let in_bytes =
        hex::decode(&clean_in).map_err(|e| CipherError::Decode(format!("Hex input error: {e}")))?;
    let key_bytes = hex::decode(&clean_key)
        .map_err(|e| CipherError::InvalidKey(format!("Hex key error: {e}")))?;
    let res = xor_bytes(&in_bytes, &key_bytes)?;
    Ok(hex::encode(res))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransformStep {
    Base64Encode,
    Base64Decode,
    HexEncode,
    HexDecode,
    BinaryEncode,
    BinaryDecode,
    UrlEncode,
    UrlDecode,
    AsciiToDecimal,
    DecimalToAscii,
    MorseEncode,
    MorseDecode,
    ReverseText,
    ReverseWords,
    Rot13,
    Atbash,
    CaesarEncrypt(u8),
    CaesarDecrypt(u8),
    VigenereEncrypt(String),
    VigenereDecrypt(String),
    AffineEncrypt { a: u8, b: u8 },
    AffineDecrypt { a: u8, b: u8 },
    RailFenceEncrypt(usize),
    RailFenceDecrypt(usize),
    BaconEncode,
    BaconDecode,
    XorText(String),
    XorHex(String),
}

pub fn apply_transform(input: &str, step: &TransformStep) -> Result<String, CipherError> {
    match step {
        TransformStep::Base64Encode => Ok(base64_encode(input)),
        TransformStep::Base64Decode => base64_decode(input),
        TransformStep::HexEncode => Ok(hex_encode(input)),
        TransformStep::HexDecode => hex_decode(input),
        TransformStep::BinaryEncode => Ok(binary_encode(input)),
        TransformStep::BinaryDecode => binary_decode(input),
        TransformStep::UrlEncode => Ok(url_encode(input)),
        TransformStep::UrlDecode => url_decode(input),
        TransformStep::AsciiToDecimal => Ok(ascii_to_decimal(input)),
        TransformStep::DecimalToAscii => decimal_to_ascii(input),
        TransformStep::MorseEncode => Ok(morse_encode(input)),
        TransformStep::MorseDecode => morse_decode(input),
        TransformStep::ReverseText => Ok(reverse_text(input)),
        TransformStep::ReverseWords => Ok(reverse_words(input)),
        TransformStep::Rot13 => Ok(rot13(input)),
        TransformStep::Atbash => Ok(atbash(input)),
        TransformStep::CaesarEncrypt(shift) => Ok(caesar_encrypt(input, *shift)),
        TransformStep::CaesarDecrypt(shift) => Ok(caesar_decrypt(input, *shift)),
        TransformStep::VigenereEncrypt(key) => Ok(vigenere_encrypt(input, key)),
        TransformStep::VigenereDecrypt(key) => Ok(vigenere_decrypt(input, key)),
        TransformStep::AffineEncrypt { a, b } => affine_encrypt(input, *a, *b),
        TransformStep::AffineDecrypt { a, b } => affine_decrypt(input, *a, *b),
        TransformStep::RailFenceEncrypt(rails) => rail_fence_encrypt(input, *rails),
        TransformStep::RailFenceDecrypt(rails) => rail_fence_decrypt(input, *rails),
        TransformStep::BaconEncode => Ok(bacon_encode(input)),
        TransformStep::BaconDecode => bacon_decode(input),
        TransformStep::XorText(key) => xor_text_to_hex(input, key),
        TransformStep::XorHex(key) => xor_hex_to_text(input, key),
    }
}

pub fn apply_pipeline(input: &str, steps: &[TransformStep]) -> Result<String, CipherError> {
    let mut current = input.to_string();
    for step in steps {
        current = apply_transform(&current, step)?;
    }
    Ok(current)
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

    #[test]
    fn test_reverse_text() {
        assert_eq!(reverse_text("Specter"), "retcepS");
        assert_eq!(reverse_text(&reverse_text("hello")), "hello");
    }

    #[test]
    fn test_reverse_words() {
        assert_eq!(reverse_words("the quick brown fox"), "fox brown quick the");
    }

    #[test]
    fn test_rail_fence_roundtrip() {
        let text = "WE ARE DISCOVERED FLEE AT ONCE";
        let encrypted = rail_fence_encrypt(text, 3).unwrap();
        assert_eq!(encrypted, "WRIVDETCEAEDSOEE LEA NE  CRF O");
        let decrypted = rail_fence_decrypt(&encrypted, 3).unwrap();
        assert_eq!(decrypted, text);

        let text2 = "hello world";
        let enc2 = rail_fence_encrypt(text2, 4).unwrap();
        assert_eq!(rail_fence_decrypt(&enc2, 4).unwrap(), text2);
    }

    #[test]
    fn test_rail_fence_invalid_rails() {
        assert!(rail_fence_encrypt("hello", 1).is_err());
        assert!(rail_fence_decrypt("hello", 0).is_err());
    }

    #[test]
    fn test_affine_roundtrip() {
        let text = "AFFINE CIPHER! Example text 123";
        let a = 5;
        let b = 8;
        let encrypted = affine_encrypt(text, a, b).unwrap();
        assert_eq!(encrypted, "IHHWVC SWFRCP! Ctiqflc zctz 123");
        let decrypted = affine_decrypt(&encrypted, a, b).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn test_affine_invalid_a() {
        assert!(affine_encrypt("hello", 2, 3).is_err());
        assert!(affine_encrypt("hello", 13, 3).is_err());
        assert!(affine_decrypt("hello", 4, 3).is_err());
    }

    #[test]
    fn test_bacon_roundtrip() {
        let text = "HELLO WORLD";
        let encoded = bacon_encode(text);
        assert_eq!(
            encoded,
            "AABBB AABAA ABABB ABABB ABBBA / BABBA ABBBA BAAAB ABABB AAABB"
        );
        let decoded = bacon_decode(&encoded).unwrap();
        assert_eq!(decoded, text);
    }

    #[test]
    fn test_bacon_decode_invalid() {
        assert!(bacon_decode("AAAA").is_err()); // 4 chars
        assert!(bacon_decode("AAAAX").is_err()); // 'X' not A/B
        assert!(bacon_decode("BBBBB").is_err()); // 31 out of range 0-25
    }

    #[test]
    fn test_xor_text_to_hex_and_back() {
        let text = "Secret Message 123";
        let key = "key42";
        let hex_out = xor_text_to_hex(text, key).unwrap();
        let decrypted = xor_hex_to_text(&hex_out, key).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn test_xor_hex_with_hex() {
        let hex_a = "1c0111001f010100061a024b53535009181c";
        let hex_b = "686974207468652062756c6c277320657965";
        let res = xor_hex_with_hex(hex_a, hex_b).unwrap();
        assert_eq!(res, "746865206b696420646f6e277420706c6179");
    }

    #[test]
    fn test_xor_empty_key_errors() {
        assert!(xor_text_to_hex("hello", "").is_err());
        assert!(xor_hex_to_text("0102", "").is_err());
    }

    #[test]
    fn test_apply_pipeline_chained() {
        let original = "Pipeline Test 2026!";
        let pipeline = vec![
            TransformStep::Base64Encode,
            TransformStep::HexEncode,
            TransformStep::HexDecode,
            TransformStep::Base64Decode,
        ];
        let res = apply_pipeline(original, &pipeline).unwrap();
        assert_eq!(res, original);

        let cipher_pipeline = vec![
            TransformStep::Rot13,
            TransformStep::Atbash,
            TransformStep::ReverseText,
        ];
        let enc = apply_pipeline("hello", &cipher_pipeline).unwrap();
        // Invert in reverse order
        let invert_pipeline = vec![
            TransformStep::ReverseText,
            TransformStep::Atbash,
            TransformStep::Rot13,
        ];
        let dec = apply_pipeline(&enc, &invert_pipeline).unwrap();
        assert_eq!(dec, "hello");
    }

    #[test]
    fn test_apply_pipeline_error_propagation() {
        let pipeline = vec![
            TransformStep::HexDecode, // "hello" is not valid hex
            TransformStep::Rot13,
        ];
        assert!(apply_pipeline("hello", &pipeline).is_err());
    }
}

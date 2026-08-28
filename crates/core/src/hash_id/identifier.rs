use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3512,
    Bcrypt,
    Ntlm,
    Mysql3,
    Mysql41,
    Ripemd160,
    Sha3224,
    Sha3256,
    Sha3384,
    Sha3512Len,
    Blake2b,
    Blake2s,
    Adler32,
    Crc32,
    Crc64,
    Gost,
    Whirlpool,
    Unknown,
}

impl HashType {
    pub fn name(&self) -> &str {
        match self {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA-1",
            HashType::Sha224 => "SHA-224",
            HashType::Sha256 => "SHA-256",
            HashType::Sha384 => "SHA-384",
            HashType::Sha512 => "SHA-512",
            HashType::Sha3512 => "SHA3-512",
            HashType::Bcrypt => "bcrypt",
            HashType::Ntlm => "NTLM",
            HashType::Mysql3 => "MySQL < 4.1",
            HashType::Mysql41 => "MySQL 4.1+",
            HashType::Ripemd160 => "RIPEMD-160",
            HashType::Sha3224 => "SHA3-224",
            HashType::Sha3256 => "SHA3-256",
            HashType::Sha3384 => "SHA3-384",
            HashType::Sha3512Len => "SHA3-512",
            HashType::Blake2b => "BLAKE2b",
            HashType::Blake2s => "BLAKE2s",
            HashType::Adler32 => "Adler32",
            HashType::Crc32 => "CRC32",
            HashType::Crc64 => "CRC64",
            HashType::Gost => "GOST R 34.11-94",
            HashType::Whirlpool => "Whirlpool",
            HashType::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Identification {
    pub hash_type: HashType,
    pub confidence: f64,
    pub length: usize,
    pub charset: String,
}

pub fn identify(input: &str) -> Vec<Identification> {
    let trimmed = input.trim();
    let len = trimmed.len();
    let charset = detect_charset(trimmed);

    let mut results: Vec<Identification> = Vec::new();

    if is_bcrypt(trimmed) {
        results.push(Identification {
            hash_type: HashType::Bcrypt,
            confidence: 0.95,
            length: len,
            charset: charset.clone(),
        });
        return results;
    }

    if is_all_hex(trimmed) {
        macro_rules! match_len {
            ($l:expr, $ht:expr, $conf:expr) => {
                if len == $l {
                    results.push(Identification {
                        hash_type: $ht,
                        confidence: $conf,
                        length: len,
                        charset: charset.clone(),
                    });
                }
            };
        }

        match_len!(32, HashType::Md5, 0.9);
        match_len!(40, HashType::Sha1, 0.9);
        match_len!(56, HashType::Sha224, 0.85);
        match_len!(64, HashType::Sha256, 0.9);
        match_len!(96, HashType::Sha384, 0.85);
        match_len!(128, HashType::Sha512, 0.9);
        match_len!(16, HashType::Mysql3, 0.7);
        match_len!(40, HashType::Ripemd160, 0.8);
        match_len!(56, HashType::Sha3224, 0.8);
        match_len!(64, HashType::Sha3256, 0.8);
        match_len!(96, HashType::Sha3384, 0.8);
        match_len!(128, HashType::Sha3512, 0.8);
    }

    if is_mysql41(trimmed) {
        results.push(Identification {
            hash_type: HashType::Mysql41,
            confidence: 0.98,
            length: len,
            charset: charset.clone(),
        });
    }

    // Md5/Sha1/Sha256 are already pushed by the length-matching block above.

    if len == 32 && is_all_uppercase_hex(trimmed) {
        results.push(Identification {
            hash_type: HashType::Ntlm,
            confidence: 0.85,
            length: len,
            charset: charset.clone(),
        });
    }

    if results.is_empty() {
        results.push(Identification {
            hash_type: HashType::Unknown,
            confidence: 0.0,
            length: len,
            charset,
        });
    }

    results
}

fn detect_charset(s: &str) -> String {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in s.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c.is_ascii_punctuation() {
            has_special = true;
        } else if !c.is_ascii() {
            return "unicode".to_string();
        }
    }

    let mut parts = Vec::new();
    if has_lower {
        parts.push("lower");
    }
    if has_upper {
        parts.push("upper");
    }
    if has_digit {
        parts.push("digit");
    }
    if has_special {
        parts.push("special");
    }
    if parts.is_empty() {
        return "unknown".to_string();
    }
    parts.join("+")
}

fn is_all_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_all_uppercase_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c.is_ascii_uppercase())
}

fn is_bcrypt(s: &str) -> bool {
    if s.len() != 60 || !(s.starts_with("$2a$") || s.starts_with("$2b$") || s.starts_with("$2y$")) {
        return false;
    }
    let Some(cost) = s.get(4..6).and_then(|value| value.parse::<u8>().ok()) else {
        return false;
    };
    (4..=31).contains(&cost) && s.as_bytes().get(6) == Some(&b'$')
}

fn is_mysql41(s: &str) -> bool {
    s.len() == 41 && s.starts_with('*') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_md5() {
        let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Md5));
    }

    #[test]
    fn test_identify_sha1() {
        let hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Sha1));
    }

    #[test]
    fn test_identify_sha256() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Sha256));
    }

    #[test]
    fn test_identify_sha512() {
        let hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Sha512));
    }

    #[test]
    fn test_identify_bcrypt() {
        let hash = "$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Bcrypt));
    }

    #[test]
    fn test_identify_ntlm() {
        let hash = "209C6174DA490CAEB422F3FA5A7AE71D";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Ntlm));
    }

    #[test]
    fn test_identify_mysql41() {
        let hash = "*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Mysql41));
    }

    #[test]
    fn test_unknown() {
        let hash = "xxxx";
        let results = identify(hash);
        assert!(results.iter().any(|r| r.hash_type == HashType::Unknown));
    }

    #[test]
    fn test_detect_charset_lower_hex() {
        let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
        let cs = detect_charset(hash);
        assert_eq!(cs, "lower+digit");
    }

    #[test]
    fn test_detect_charset_upper_hex() {
        let hash = "209C6174DA490CAEB422F3FA5A7AE71D";
        let cs = detect_charset(hash);
        assert_eq!(cs, "upper+digit");
    }
}

use crate::hash_id::{identify, Identification};
use serde::{Deserialize, Serialize};
use sha1::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Ntlm,
    Mysql3,
    Mysql41,
}

impl HashAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Md5 => "MD5",
            HashAlgorithm::Sha1 => "SHA-1",
            HashAlgorithm::Sha224 => "SHA-224",
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha384 => "SHA-384",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Ntlm => "NTLM",
            HashAlgorithm::Mysql3 => "MySQL < 4.1",
            HashAlgorithm::Mysql41 => "MySQL 4.1+",
        }
    }

    pub fn id_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Md5 => "md5",
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha224 => "sha224",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
            HashAlgorithm::Ntlm => "ntlm",
            HashAlgorithm::Mysql3 => "mysql3",
            HashAlgorithm::Mysql41 => "mysql41",
        }
    }

    pub fn from_id(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "md5" => Some(HashAlgorithm::Md5),
            "sha1" | "sha-1" => Some(HashAlgorithm::Sha1),
            "sha224" | "sha-224" => Some(HashAlgorithm::Sha224),
            "sha256" | "sha-256" => Some(HashAlgorithm::Sha256),
            "sha384" | "sha-384" => Some(HashAlgorithm::Sha384),
            "sha512" | "sha-512" => Some(HashAlgorithm::Sha512),
            "ntlm" => Some(HashAlgorithm::Ntlm),
            "mysql3" | "mysql" => Some(HashAlgorithm::Mysql3),
            "mysql41" | "mysql4.1" => Some(HashAlgorithm::Mysql41),
            _ => None,
        }
    }

    pub fn all() -> &'static [HashAlgorithm] {
        &[
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Ntlm,
            HashAlgorithm::Mysql3,
            HashAlgorithm::Mysql41,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashDigestEntry {
    pub algorithm: String,
    pub algorithm_id: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextHashResult {
    pub algorithm: String,
    pub algorithm_id: String,
    pub input_length: usize,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiHashResult {
    pub input_length: usize,
    pub digests: Vec<HashDigestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HashComparisonResult {
    pub matches: bool,
    pub first_hash: String,
    pub second_hash: String,
    pub first_types: Vec<Identification>,
    pub second_types: Vec<Identification>,
    pub details: String,
}

pub enum StreamingHasher {
    Md5(md5::Context),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Ntlm(Vec<u8>),
    Mysql3 { nr: u64, add: u64, nr2: u64 },
    Mysql41(sha1::Sha1),
}

impl StreamingHasher {
    pub fn new(algo: HashAlgorithm) -> Self {
        match algo {
            HashAlgorithm::Md5 => StreamingHasher::Md5(md5::Context::new()),
            HashAlgorithm::Sha1 => StreamingHasher::Sha1(sha1::Sha1::new()),
            HashAlgorithm::Sha224 => StreamingHasher::Sha224(sha2::Sha224::new()),
            HashAlgorithm::Sha256 => StreamingHasher::Sha256(sha2::Sha256::new()),
            HashAlgorithm::Sha384 => StreamingHasher::Sha384(sha2::Sha384::new()),
            HashAlgorithm::Sha512 => StreamingHasher::Sha512(sha2::Sha512::new()),
            HashAlgorithm::Ntlm => StreamingHasher::Ntlm(Vec::new()),
            HashAlgorithm::Mysql3 => StreamingHasher::Mysql3 {
                nr: 1_345_345_333u64,
                add: 7u64,
                nr2: 0x1234_5671u64,
            },
            HashAlgorithm::Mysql41 => StreamingHasher::Mysql41(sha1::Sha1::new()),
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        match self {
            StreamingHasher::Md5(ctx) => ctx.consume(chunk),
            StreamingHasher::Sha1(ctx) => ctx.update(chunk),
            StreamingHasher::Sha224(ctx) => ctx.update(chunk),
            StreamingHasher::Sha256(ctx) => ctx.update(chunk),
            StreamingHasher::Sha384(ctx) => ctx.update(chunk),
            StreamingHasher::Sha512(ctx) => ctx.update(chunk),
            StreamingHasher::Ntlm(buf) => buf.extend_from_slice(chunk),
            StreamingHasher::Mysql3 { nr, add, nr2 } => {
                for &byte in chunk.iter().filter(|&&b| b != b' ' && b != b'\t') {
                    let value = byte as u64;
                    *nr ^= ((*nr & 63).wrapping_add(*add).wrapping_mul(value)).wrapping_add(*nr << 8);
                    *nr2 = nr2.wrapping_add((*nr2 << 8) ^ *nr);
                    *add = add.wrapping_add(value);
                }
            }
            StreamingHasher::Mysql41(ctx) => ctx.update(chunk),
        }
    }

    pub fn finalize(self) -> String {
        match self {
            StreamingHasher::Md5(ctx) => format!("{:x}", ctx.compute()),
            StreamingHasher::Sha1(ctx) => format!("{:x}", ctx.finalize()),
            StreamingHasher::Sha224(ctx) => format!("{:x}", ctx.finalize()),
            StreamingHasher::Sha256(ctx) => format!("{:x}", ctx.finalize()),
            StreamingHasher::Sha384(ctx) => format!("{:x}", ctx.finalize()),
            StreamingHasher::Sha512(ctx) => format!("{:x}", ctx.finalize()),
            StreamingHasher::Ntlm(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                let encoded: Vec<u16> = s.encode_utf16().collect();
                let utf16_bytes: Vec<u8> = encoded.iter().flat_map(|c| c.to_le_bytes()).collect();
                let digest = md4::Md4::digest(&utf16_bytes);
                hex::encode_upper(digest)
            }
            StreamingHasher::Mysql3 { nr, nr2, .. } => {
                format!("{:016X}", ((nr & 0x7fff_ffff) << 32) | (nr2 & 0x7fff_ffff))
            }
            StreamingHasher::Mysql41(ctx) => {
                let stage1 = ctx.finalize();
                let stage2 = sha1::Sha1::digest(stage1);
                format!("*{:X}", stage2)
            }
        }
    }
}

pub fn compute_hash(algo: HashAlgorithm, data: &[u8]) -> String {
    let mut hasher = StreamingHasher::new(algo);
    hasher.update(data);
    hasher.finalize()
}

pub fn compute_hash_text(algo: HashAlgorithm, text: &str) -> TextHashResult {
    let hash = compute_hash(algo, text.as_bytes());
    TextHashResult {
        algorithm: algo.name().to_string(),
        algorithm_id: algo.id_str().to_string(),
        input_length: text.len(),
        hash,
    }
}

pub fn compute_all_hashes(data: &[u8]) -> Vec<HashDigestEntry> {
    HashAlgorithm::all()
        .iter()
        .map(|&algo| HashDigestEntry {
            algorithm: algo.name().to_string(),
            algorithm_id: algo.id_str().to_string(),
            hash: compute_hash(algo, data),
        })
        .collect()
}

pub fn compute_all_hashes_text(text: &str) -> MultiHashResult {
    MultiHashResult {
        input_length: text.len(),
        digests: compute_all_hashes(text.as_bytes()),
    }
}

pub fn compare_hashes(first: &str, second: &str) -> HashComparisonResult {
    let clean_a = first.trim();
    let clean_b = second.trim();

    let matches = !clean_a.is_empty()
        && !clean_b.is_empty()
        && clean_a.eq_ignore_ascii_case(clean_b);

    let first_types = identify(clean_a);
    let second_types = identify(clean_b);

    let details = if clean_a.is_empty() || clean_b.is_empty() {
        "Please provide two hashes to compare.".to_string()
    } else if matches {
        format!(
            "MATCH: Hashes are identical (case-insensitive, {} chars). Likely type: {}.",
            clean_a.len(),
            first_types
                .first()
                .map(|t| t.hash_type.name())
                .unwrap_or("Unknown")
        )
    } else if clean_a.len() != clean_b.len() {
        format!(
            "NO MATCH: Length mismatch (Hash 1: {} chars, Hash 2: {} chars).",
            clean_a.len(),
            clean_b.len()
        )
    } else {
        format!(
            "NO MATCH: Same length ({} chars) but digest content differs.",
            clean_a.len()
        )
    };

    HashComparisonResult {
        matches,
        first_hash: clean_a.to_string(),
        second_hash: clean_b.to_string(),
        first_types,
        second_types,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_all_known_vectors() {
        assert_eq!(
            compute_hash(HashAlgorithm::Md5, b"password"),
            "5f4dcc3b5aa765d61d8327deb882cf99"
        );
        assert_eq!(
            compute_hash(HashAlgorithm::Sha1, b"password"),
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        );
        assert_eq!(
            compute_hash(HashAlgorithm::Sha256, b"admin"),
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
        );
        assert_eq!(
            compute_hash(HashAlgorithm::Ntlm, b"admin"),
            "209C6174DA490CAEB422F3FA5A7AE634"
        );
        assert_eq!(
            compute_hash(HashAlgorithm::Mysql3, b""),
            "5030573512345671"
        );
        assert_eq!(
            compute_hash(HashAlgorithm::Mysql41, b""),
            "*BE1BDEC0AA74B4DCB079943E70528096CCA985F8"
        );
    }

    #[test]
    fn test_streaming_chunked_equivalence() {
        let text = b"The quick brown fox jumps over the lazy dog. Fast in-browser hashing!";
        for &algo in HashAlgorithm::all() {
            let direct = compute_hash(algo, text);
            let mut streaming = StreamingHasher::new(algo);
            for chunk in text.chunks(7) {
                streaming.update(chunk);
            }
            let streamed = streaming.finalize();
            assert_eq!(direct, streamed, "Mismatch for algorithm {:?}", algo);
        }
    }

    #[test]
    fn test_compare_hashes() {
        let h1 = "5f4dcc3b5aa765d61d8327deb882cf99";
        let h2 = "5F4DCC3B5AA765D61D8327DEB882CF99";
        let res = compare_hashes(h1, h2);
        assert!(res.matches);

        let h3 = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
        let res2 = compare_hashes(h1, h3);
        assert!(!res2.matches);
    }
}

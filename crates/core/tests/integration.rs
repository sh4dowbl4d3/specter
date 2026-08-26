use devastator_core::cipher_tools::ciphers::*;
use devastator_core::cipher_tools::detect_cipher;
use devastator_core::cracker::brute_force::*;
use devastator_core::cracker::dictionary::*;
use devastator_core::hash_id::*;

// ── Hash identification tests ─────────────────────────────────

#[test]
fn identify_all_known_types() {
    let cases: Vec<(&str, HashType)> = vec![
        ("5f4dcc3b5aa765d61d8327deb882cf99", HashType::Md5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", HashType::Sha1),
        ("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", HashType::Sha224),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", HashType::Sha256),
        ("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", HashType::Sha384),
        ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", HashType::Sha512),
        ("$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", HashType::Bcrypt),
        ("209C6174DA490CAEB422F3FA5A7AE71D", HashType::Ntlm),
        ("*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4", HashType::Mysql41),
    ];
    for (hash, expected) in cases {
        let results = identify(hash);
        assert!(
            results.iter().any(|r| r.hash_type == expected),
            "identify({}): expected {:?} not found in {:?}",
            hash,
            expected,
            results.iter().map(|r| &r.hash_type).collect::<Vec<_>>()
        );
    }
}

#[test]
fn identify_unknown_returns_unknown() {
    let results = identify("zzzzz");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].hash_type, HashType::Unknown);
}

#[test]
fn identify_lowercase_ntlm_is_md5_and_also_ntlm_via_cracker() {
    let results = identify("209c6174da490caeb422f3fa5a7ae634");
    assert!(results.iter().any(|r| r.hash_type == HashType::Md5));
    assert!(!results.iter().any(|r| r.hash_type == HashType::Ntlm));

    let cracked = crack_from_list("209c6174da490caeb422f3fa5a7ae634", "admin\npassword\n");
    let r = cracked.unwrap();
    assert_eq!(r.plaintext.as_deref(), Some("admin"));
    assert_eq!(r.method, "dictionary (NTLM)");
}

// ── Hash function tests (known test vectors) ──────────────────

#[test]
fn hash_functions_known_vectors() {
    assert_eq!(hash_md5(""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hash_md5("password"), "5f4dcc3b5aa765d61d8327deb882cf99");
    assert_eq!(hash_sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        hash_sha1("password"),
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    );
    assert_eq!(
        hash_sha224(""),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );
    assert_eq!(
        hash_sha256(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hash_sha256("admin"),
        "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    );
    assert_eq!(hash_sha384(""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    let sha512_empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    assert_eq!(hash_sha512(""), sha512_empty);
    assert_eq!(hash_ntlm("admin"), "209C6174DA490CAEB422F3FA5A7AE634");
    assert_eq!(hash_mysql3(""), "5030573512345671");
    assert_eq!(
        hash_mysql41(""),
        "*BE1BDEC0AA74B4DCB079943E70528096CCA985F8"
    );
}

// ── Dictionary cracking tests ─────────────────────────────────

#[test]
fn crack_all_supported_types() {
    let wordlist = "password\nadmin\ntest\nhello\nworld\n";

    let cases: Vec<(&str, &str, &str)> = vec![
        ("5f4dcc3b5aa765d61d8327deb882cf99", "password", "MD5"),
        ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "password", "SHA-1"),
        ("90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809", "test", "SHA-224"),
        ("8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", "admin", "SHA-256"),
        ("768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9", "test", "SHA-384"),
        ("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", "test", "SHA-512"),
        ("209C6174DA490CAEB422F3FA5A7AE634", "admin", "NTLM"),
    ];

    for (hash, expected_plain, expected_method) in cases {
        let result = crack_from_list(hash, wordlist);
        assert!(result.is_some(), "crack_from_list({}) returned None", hash);
        let r = result.unwrap();
        assert_eq!(
            r.plaintext.as_deref(),
            Some(expected_plain),
            "crack_from_list({}): expected plaintext {:?}, got {:?}",
            hash,
            expected_plain,
            r.plaintext
        );
        assert!(
            r.method.contains(expected_method),
            "crack_from_list({}): expected method to contain {:?}, got {:?}",
            hash,
            expected_method,
            r.method
        );
    }
}

#[test]
fn crack_not_found_returns_none_plaintext() {
    let wordlist = "password\nadmin\n";
    let result = crack_from_list("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", wordlist);
    assert!(result.is_some());
    assert_eq!(result.unwrap().plaintext, None);
}

#[test]
fn crack_empty_wordlist_returns_none_plaintext() {
    let result = crack_from_list("5f4dcc3b5aa765d61d8327deb882cf99", "");
    assert!(result.is_some());
    assert_eq!(result.unwrap().plaintext, None);
}

#[test]
fn crack_case_insensitive_hash() {
    let wordlist = "password\n";
    let upper = crack_from_list("5F4DCC3B5AA765D61D8327DEB882CF99", wordlist);
    let lower = crack_from_list("5f4dcc3b5aa765d61d8327deb882cf99", wordlist);
    assert_eq!(upper.unwrap().plaintext, lower.unwrap().plaintext);
}

// ── Brute-force tests ─────────────────────────────────────────

#[test]
fn brute_force_md5_finds_password_in_range() {
    let config = BruteForceConfig {
        hash: hash_md5("admin"),
        max_length: 5,
        charset: "lower".to_string(),
    };
    let result = brute_force_crack(&config);
    assert!(result.cracked);
    assert_eq!(result.plaintext.unwrap(), "admin");
}

#[test]
fn brute_force_sha1_finds_short_password() {
    let config = BruteForceConfig {
        hash: hash_sha1("test"),
        max_length: 4,
        charset: "lower".to_string(),
    };
    let result = brute_force_crack(&config);
    assert!(result.cracked);
    assert_eq!(result.plaintext.unwrap(), "test");
}

#[test]
fn brute_force_sha256_finds_short_password() {
    let config = BruteForceConfig {
        hash: hash_sha256("test"),
        max_length: 4,
        charset: "lower".to_string(),
    };
    let result = brute_force_crack(&config);
    assert!(result.cracked);
    assert_eq!(result.plaintext.unwrap(), "test");
}

#[test]
fn brute_force_limit_20m_computations() {
    let config = BruteForceConfig {
        hash: "00000000000000000000000000000000".to_string(),
        max_length: 6,
        charset: "alnum".to_string(),
    };
    let result = brute_force_crack(&config);
    assert!(!result.cracked);
    assert!(result.attempts <= 20_000_000);
}

// ── Cipher encode/decode roundtrip tests ──────────────────────

#[test]
fn cipher_roundtrips_preserve_content() {
    let inputs = vec!["hello", "world", "test123", "HELLO WORLD", ""];

    for input in inputs {
        assert_eq!(
            base64_decode(&base64_encode(input)).unwrap(),
            input,
            "Base64 roundtrip failed for {:?}",
            input
        );
        assert_eq!(
            hex_decode(&hex_encode(input)).unwrap(),
            input,
            "Hex roundtrip failed for {:?}",
            input
        );
        assert_eq!(
            binary_decode(&binary_encode(input)).unwrap(),
            input,
            "Binary roundtrip failed for {:?}",
            input
        );
    }
}

#[test]
fn caesar_identity() {
    for shift in 0..26u8 {
        let s = "hello world";
        let encrypted = caesar_encrypt(s, shift);
        let decrypted = caesar_decrypt(&encrypted, shift);
        assert_eq!(decrypted, s, "Caesar identity failed for shift {}", shift);
    }
}

#[test]
fn rot13_twice_is_identity() {
    let s = "the quick brown fox";
    assert_eq!(rot13(&rot13(s)), s);
}

#[test]
fn atbash_twice_is_identity() {
    let s = "hello world";
    assert_eq!(atbash(&atbash(s)), s);
}

#[test]
fn vigenere_roundtrip() {
    let cases = vec![
        ("hello", "key"),
        ("rust", "secret"),
        ("attack at dawn", "abc"),
    ];
    for (plaintext, key) in cases {
        let encrypted = vigenere_encrypt(plaintext, key);
        let decrypted = vigenere_decrypt(&encrypted, key);
        assert_eq!(
            decrypted, plaintext,
            "Vigenere roundtrip failed for plaintext={:?} key={:?}",
            plaintext, key
        );
    }
}

// ── Cipher detection tests ────────────────────────────────────

#[test]
fn detect_cipher_base64() {
    let results = detect_cipher("aGVsbG8gd29ybGQ=");
    assert!(results.iter().any(|r| r.cipher_type == CipherType::Base64));
}

#[test]
fn detect_cipher_hex() {
    let results = detect_cipher("68656c6c6f");
    assert!(results.iter().any(|r| r.cipher_type == CipherType::Hex));
}

#[test]
fn detect_cipher_binary() {
    let results = detect_cipher("01101000 01100101 01101100 01101100 01101111");
    assert!(results.iter().any(|r| r.cipher_type == CipherType::Binary));
}

#[test]
fn detect_cipher_rot13() {
    let results = detect_cipher("uryyb jbeyq");
    assert!(results.iter().any(|r| r.cipher_type == CipherType::Rot13));
}

// ── End-to-end: identify → crack (cross-module) ───────────────

#[test]
fn identify_then_crack() {
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let ident = identify(hash);
    assert!(!ident.is_empty());
    assert!(ident.iter().any(|i| i.hash_type == HashType::Md5));

    let cracked = crack_from_list(hash, "password\n");
    assert!(cracked.is_some());
    let r = cracked.unwrap();
    assert_eq!(r.plaintext.as_deref(), Some("password"));
}

#[test]
fn identify_sha256_then_crack_all_charsets() {
    let hash = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
    let ident = identify(hash);
    assert!(ident.iter().any(|i| i.hash_type == HashType::Sha256));

    let cracked = crack_from_list(hash, "admin\n");
    assert_eq!(cracked.unwrap().plaintext.as_deref(), Some("admin"));
}

// ── Ensure no side effects (pure functions) ───────────────────

#[test]
fn identify_is_pure() {
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let r1 = identify(hash);
    let r2 = identify(hash);
    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.hash_type, b.hash_type);
        assert!((a.confidence - b.confidence).abs() < f64::EPSILON);
    }
}

#[test]
fn crack_from_list_is_pure() {
    let wordlist = "password\nadmin\ntest\n";
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let r1 = crack_from_list(hash, wordlist);
    let r2 = crack_from_list(hash, wordlist);
    assert_eq!(r1.unwrap().plaintext, r2.unwrap().plaintext);
}

#[test]
fn hash_functions_are_deterministic() {
    let inputs = ["", "a", "hello", "password", "admin", "test"];
    for input in &inputs {
        assert_eq!(hash_md5(input), hash_md5(input));
        assert_eq!(hash_sha1(input), hash_sha1(input));
        assert_eq!(hash_sha256(input), hash_sha256(input));
        assert_eq!(hash_ntlm(input), hash_ntlm(input));
    }
}

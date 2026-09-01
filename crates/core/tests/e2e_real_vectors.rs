use specter_core::cipher_tools::ciphers::*;
use specter_core::cipher_tools::detect_cipher;
use specter_core::cracker::brute_force::*;
use specter_core::cracker::dictionary::*;
use specter_core::hash_id::*;
use specter_core::hasher::*;
use specter_core::history::{NewHistoryEntry, OperationType, SessionHistory};

// =========================================================================
// 1. Real NIST / RFC Cryptographic Hash Vectors
// =========================================================================

#[test]
fn e2e_real_vectors_rfc1321_md5() {
    let cases = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    for (input, expected) in cases {
        let digest = compute_hash(HashAlgorithm::Md5, input.as_bytes());
        assert_eq!(digest, expected, "MD5 failed for input: {input:?}");
    }
}

#[test]
fn e2e_real_vectors_rfc3174_sha1() {
    let cases = [
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ];
    for (input, expected) in cases {
        let digest = compute_hash(HashAlgorithm::Sha1, input.as_bytes());
        assert_eq!(digest, expected, "SHA-1 failed for input: {input:?}");
    }
}

#[test]
fn e2e_real_vectors_fips180_4_sha256() {
    let cases = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
    ];
    for (input, expected) in cases {
        let digest = compute_hash(HashAlgorithm::Sha256, input.as_bytes());
        assert_eq!(digest, expected, "SHA-256 failed for input: {input:?}");
    }
}

#[test]
fn e2e_real_vectors_fips180_4_sha512() {
    let cases = [
        (
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ];
    for (input, expected) in cases {
        let digest = compute_hash(HashAlgorithm::Sha512, input.as_bytes());
        assert_eq!(digest, expected, "SHA-512 failed for input: {input:?}");
    }
}

#[test]
fn e2e_real_vectors_ntlm_and_mysql() {
    // NTLM real vectors (MD4(UTF-16LE(password)))
    assert_eq!(
        compute_hash(HashAlgorithm::Ntlm, b"").to_lowercase(),
        "31d6cfe0d16ae931b73c59d7e0c089c0"
    );
    assert_eq!(
        compute_hash(HashAlgorithm::Ntlm, b"password").to_lowercase(),
        "8846f7eaee8fb117ad06bdd830b7586c"
    );
    assert_eq!(
        compute_hash(HashAlgorithm::Ntlm, b"Administrator").to_lowercase(),
        "d144986c6122b1b1654ba39932465528"
    );

    // MySQL 3.23 / 4.0 old password
    assert_eq!(
        compute_hash(HashAlgorithm::Mysql3, b"mypass"),
        "6F8C114B58F2CE9E"
    );

    // MySQL 4.1+ (SHA1(SHA1(password))) prefixed with *
    assert_eq!(
        compute_hash(HashAlgorithm::Mysql41, b"mypass"),
        "*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4"
    );
}

// =========================================================================
// 2. Real Hash Identification & Candidate Guidance
// =========================================================================

#[test]
fn e2e_real_identification_suite() {
    // 32-hex lowercase (MD5)
    let md5_candidates = identify("5f4dcc3b5aa765d61d8327deb882cf99");
    assert!(md5_candidates.iter().any(|c| c.hash_type == HashType::Md5));

    // 32-hex uppercase (NTLM)
    let ntlm_candidates = identify("8846F7EAEE8FB117AD06BDD830B7586C");
    assert!(ntlm_candidates
        .iter()
        .any(|c| c.hash_type == HashType::Ntlm));

    // 40-hex (SHA-1 / MySQL4.1 / RIPEMD-160)
    let sha1_candidates = identify("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    assert!(sha1_candidates
        .iter()
        .any(|c| c.hash_type == HashType::Sha1));

    // 64-hex (SHA-256 / SHA3-256)
    let sha256_candidates =
        identify("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    assert!(sha256_candidates
        .iter()
        .any(|c| c.hash_type == HashType::Sha256));

    // bcrypt ($2b$ prefix)
    let bcrypt_candidates =
        identify("$2b$12$e86gKk/k6rZkO.d7Q0Jp0O7U5g2t3w1y2z3x4c5v6b7n8m9a0s1d2");
    assert_eq!(bcrypt_candidates[0].hash_type, HashType::Bcrypt);
    assert_eq!(bcrypt_candidates[0].hash_type.name(), "bcrypt");
}

// =========================================================================
// 3. Real Hash Comparison Engine
// =========================================================================

#[test]
fn e2e_real_hash_comparison() {
    // Exact match with different cases and whitespace
    let res = compare_hashes(
        "  5F4DCC3B5AA765D61D8327DEB882CF99  ",
        "5f4dcc3b5aa765d61d8327deb882cf99\n",
    );
    assert!(res.matches);
    assert!(res.details.contains("MATCH"));

    // Mismatch
    let res_mismatch = compare_hashes(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "8846f7eaee8fb117ad06bdd830b7586c",
    );
    assert!(!res_mismatch.matches);
}

// =========================================================================
// 4. Real Cracking Engine (Dictionary & Bounded Brute-Force)
// =========================================================================

#[test]
fn e2e_real_dictionary_cracking() {
    let wordlist = "123456\nqwerty\nletmein\npassword\nadmin\nsecret\n";

    // MD5 for 'password'
    let md5_target = "5f4dcc3b5aa765d61d8327deb882cf99";
    let crack_md5 = crack_from_list(md5_target, wordlist).expect("Cracking should succeed");
    assert_eq!(crack_md5.plaintext.as_deref(), Some("password"));

    // SHA-256 for 'password'
    let sha256_target = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    let crack_sha256 = crack_from_list(sha256_target, wordlist).expect("Cracking should succeed");
    assert_eq!(crack_sha256.plaintext.as_deref(), Some("password"));

    // NTLM for 'password'
    let ntlm_target = "8846f7eaee8fb117ad06bdd830b7586c";
    let crack_ntlm = crack_from_list(ntlm_target, wordlist).expect("Cracking should succeed");
    assert_eq!(crack_ntlm.plaintext.as_deref(), Some("password"));
}

#[test]
fn e2e_real_bruteforce_stepping() {
    // 1. Direct batch wrapper test
    let config = BruteForceConfig {
        hash: hash_md5("cat"),
        max_length: 3,
        charset: "lower".to_string(),
    };
    let res = brute_force_crack(&config);
    assert!(res.cracked);
    assert_eq!(res.plaintext.as_deref(), Some("cat"));

    // 2. Incremental session step test
    let mut session = BruteForceSession::new(&config).unwrap();
    let outcome = session.step(50_000);
    let session_res = session.finish(outcome);
    assert!(session_res.cracked);
    assert_eq!(session_res.plaintext.as_deref(), Some("cat"));
}

// =========================================================================
// 5. Real Classical Ciphers, RFC Encodings & Heuristic Auto-Detection
// =========================================================================

#[test]
fn e2e_real_encodings_and_classical_ciphers() {
    // 1. Base64 RFC 4648
    let original = "Specter Cryptanalysis Workbench 2026";
    let b64 = base64_encode(original);
    assert_eq!(base64_decode(&b64).unwrap(), original);

    // 2. Hexadecimal
    let hex = hex_encode(original);
    assert_eq!(hex_decode(&hex).unwrap(), original);

    // 3. Binary (8-bit)
    let bin = binary_encode("Specter");
    assert_eq!(binary_decode(&bin).unwrap(), "Specter");

    // 4. URL Percent Encoding
    let url_raw = "https://specter.local/query?name=Alice & Bob+Security#100%";
    let url_enc = url_encode(url_raw);
    assert_eq!(url_decode(&url_enc).unwrap(), url_raw);

    // 5. ROT13
    let rot_raw = "The quick brown fox jumps over the lazy dog";
    let rot_enc = rot13(rot_raw);
    assert_eq!(rot13(&rot_enc), rot_raw);

    // 6. Caesar Cipher (shift 7)
    let caesar_enc = caesar_encrypt("SPECTER", 7);
    assert_eq!(caesar_decrypt(&caesar_enc, 7), "SPECTER");

    // 7. Atbash
    let atbash_enc = atbash("ABCXYZabcxyz");
    assert_eq!(atbash(&atbash_enc), "ABCXYZabcxyz");

    // 8. Vigenère Cipher
    let vigenere_key = "CRYPTO";
    let vig_enc = vigenere_encrypt("ATTACKATDAWN", vigenere_key);
    assert_eq!(vigenere_decrypt(&vig_enc, vigenere_key), "ATTACKATDAWN");

    // 9. Morse Code
    let morse_raw = "SPECTER 2026";
    let morse_enc = morse_encode(morse_raw);
    assert_eq!(morse_decode(&morse_enc).unwrap(), "SPECTER 2026");

    // 10. Rail Fence Transposition (3 rails)
    let rf_raw = "WE ARE DISCOVERED FLEE AT ONCE";
    let rf_enc = rail_fence_encrypt(rf_raw, 3).unwrap();
    assert_eq!(rail_fence_decrypt(&rf_enc, 3).unwrap(), rf_raw);

    // 11. XOR Key Streaming
    let xor_plain = "Confidential Security Audit Log";
    let xor_key = "SpecterAlphaKey";
    let xor_hex = xor_text_to_hex(xor_plain, xor_key).unwrap();
    assert_eq!(xor_hex_to_text(&xor_hex, xor_key).unwrap(), xor_plain);
}

#[test]
fn e2e_real_pipeline_chained_transforms() {
    let raw = "Mission Critical Payload 2026";
    let pipeline = vec![
        TransformStep::Base64Encode,
        TransformStep::Rot13,
        TransformStep::HexEncode,
        TransformStep::UrlEncode,
    ];
    let encoded = apply_pipeline(raw, &pipeline).unwrap();

    let inverse = vec![
        TransformStep::UrlDecode,
        TransformStep::HexDecode,
        TransformStep::Rot13,
        TransformStep::Base64Decode,
    ];
    let recovered = apply_pipeline(&encoded, &inverse).unwrap();
    assert_eq!(recovered, raw);
}

#[test]
fn e2e_real_cipher_auto_detection() {
    // Detect Base64
    let b64_candidates = detect_cipher("U3BlY3RlciBDeWJlcnNlY3VyaXR5IFdvcmtiZW5jaA==");
    assert!(b64_candidates
        .iter()
        .any(|c| c.cipher_type == CipherType::Base64));

    // Detect Hex
    let hex_candidates = detect_cipher("537065637465722032303236");
    assert!(hex_candidates
        .iter()
        .any(|c| c.cipher_type == CipherType::Hex));

    // Detect Morse
    let morse_candidates = detect_cipher("... .--. . -.-. - . .-.");
    assert_eq!(morse_candidates[0].cipher_type, CipherType::Morse);
    assert_eq!(morse_candidates[0].decoded.as_deref(), Some("SPECTER"));

    // Detect Binary
    let binary_candidates =
        detect_cipher("01010011 01110000 01100101 01100011 01110100 01100101 01110010");
    assert!(binary_candidates
        .iter()
        .any(|c| c.cipher_type == CipherType::Binary));
    assert_eq!(binary_candidates[0].decoded.as_deref(), Some("Specter"));
}

// =========================================================================
// 6. Real Chunked Streaming Hasher (File Simulation)
// =========================================================================

#[test]
fn e2e_real_streaming_file_hasher_equivalence() {
    // Generate a 1 MiB synthetic file buffer
    let mut large_buffer = Vec::with_capacity(1024 * 1024);
    for i in 0..(1024 * 1024) {
        large_buffer.push((i % 251) as u8);
    }

    for &algo in HashAlgorithm::all() {
        let single_pass = compute_hash(algo, &large_buffer);

        // Stream through in 64 KiB chunks
        let mut hasher = StreamingHasher::new(algo);
        for chunk in large_buffer.chunks(64 * 1024) {
            hasher.update(chunk);
        }
        let chunked_pass = hasher.finalize();

        assert_eq!(
            chunked_pass, single_pass,
            "Streaming chunked mismatch for algo {:?}",
            algo
        );
    }
}

// =========================================================================
// 7. Real Session History & Privacy Controls
// =========================================================================

#[test]
fn e2e_real_session_history_and_audit_export() {
    let mut history = SessionHistory::new(10);

    history.record(NewHistoryEntry::new(
        OperationType::Identify,
        "Hash Identification",
        "Identified candidate hash family MD5",
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "Candidate: MD5 (score: 95)",
        true,
        1_700_000_000_000,
    ));

    history.record(NewHistoryEntry::new(
        OperationType::CrackDictionary,
        "Dictionary Crack",
        "Recovered plaintext password in 0.02s",
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "password",
        true,
        1_700_000_001_000,
    ));

    assert_eq!(history.len(), 2);

    // Markdown export check
    let md = history.export_markdown();
    assert!(md.contains("# Specter Session Audit Log"));
    assert!(md.contains("Total Operations: **2**"));
    assert!(md.contains("Hash Identification"));
    assert!(md.contains("password"));

    // JSON export check
    let json = history.export_json().unwrap();
    assert!(json.contains("5f4dcc3b5aa765d61d8327deb882cf99"));
    assert!(json.contains("password"));

    // Privacy Wipe
    history.clear();
    assert_eq!(history.len(), 0);
    assert!(history.is_empty());
}

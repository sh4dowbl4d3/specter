use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct HashInput {
    pub hash: String,
    pub wordlist_path: Option<String>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Deserialize)]
pub struct BruteForceInput {
    pub hash: String,
    pub max_length: u8,
    pub charset: String,
}

#[derive(Deserialize)]
pub struct CipherInput {
    pub text: String,
    pub cipher: Option<String>,
    pub key: Option<String>,
    pub shift: Option<u8>,
}

pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok".to_string(),
        version: "0.1.0".to_string(),
    })
}

pub async fn hash_identify(input: web::Json<HashInput>) -> HttpResponse {
    let results = hash_id::identify(&input.hash);
    HttpResponse::Ok().json(&results)
}

pub async fn hash_crack(input: web::Json<HashInput>) -> HttpResponse {
    let wordlist = match &input.wordlist_path {
        Some(path) => std::path::PathBuf::from(path),
        None => {
            let default = std::path::PathBuf::from("wordlists/rockyou.txt");
            if default.exists() {
                default
            } else {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "No wordlist specified and default wordlists/rockyou.txt not found"
                }));
            }
        }
    };

    match cracker::crack_from_path(&input.hash, &wordlist) {
        Ok(Some(result)) => HttpResponse::Ok().json(&result),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "hash": input.hash,
            "plaintext": null,
            "method": "none"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

pub async fn hash_bruteforce(input: web::Json<BruteForceInput>) -> HttpResponse {
    if input.max_length > 6 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "max_length too high (max 6)"
        }));
    }

    let config = cracker::BruteForceConfig {
        hash: input.hash.clone(),
        max_length: input.max_length,
        charset: input.charset.clone(),
    };

    let result = cracker::brute_force_crack(&config);
    HttpResponse::Ok().json(&result)
}

pub async fn cipher_detect(input: web::Json<CipherInput>) -> HttpResponse {
    let results = cipher_tools::detect_cipher(&input.text);
    HttpResponse::Ok().json(&results)
}

pub async fn cipher_decode(input: web::Json<CipherInput>) -> HttpResponse {
    use cipher_tools::ciphers;

    let cipher = input
        .cipher
        .as_deref()
        .unwrap_or("unknown")
        .to_lowercase();

    let result = match cipher.as_str() {
        "base64" => ciphers::base64_decode(&input.text).map(|s| s),
        "hex" => ciphers::hex_decode(&input.text).map(|s| s),
        "binary" => ciphers::binary_decode(&input.text).map(|s| s),
        "rot13" => Ok(ciphers::rot13(&input.text)),
        "atbash" => Ok(ciphers::atbash(&input.text)),
        "caesar" => {
            let shift = input.shift.unwrap_or(0);
            Ok(ciphers::caesar_decrypt(&input.text, shift))
        }
        "vigenere" => {
            let key = input.key.as_deref().unwrap_or("");
            Ok(ciphers::vigenere_decrypt(&input.text, key))
        }
        _ => {
            let detections = cipher_tools::detect_cipher(&input.text);
            if detections.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Unknown cipher type and auto-detection failed"
                }));
            }
            return HttpResponse::Ok().json(&detections);
        }
    };

    match result {
        Ok(decoded) => HttpResponse::Ok().json(serde_json::json!({
            "decoded": decoded,
            "cipher": cipher,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

pub async fn cipher_encode(input: web::Json<CipherInput>) -> HttpResponse {
    use cipher_tools::ciphers;

    let cipher = input
        .cipher
        .as_deref()
        .unwrap_or("unknown")
        .to_lowercase();

    let result = match cipher.as_str() {
        "base64" => Ok(ciphers::base64_encode(&input.text)),
        "hex" => Ok(ciphers::hex_encode(&input.text)),
        "binary" => Ok(ciphers::binary_encode(&input.text)),
        "rot13" => Ok(ciphers::rot13(&input.text)),
        "atbash" => Ok(ciphers::atbash(&input.text)),
        "caesar" => {
            let shift = input.shift.unwrap_or(0);
            Ok(ciphers::caesar_encrypt(&input.text, shift))
        }
        "vigenere" => {
            let key = input.key.as_deref().unwrap_or("");
            Ok(ciphers::vigenere_encrypt(&input.text, key))
        }
        _ => Err(cipher_tools::CipherError::Encode(format!(
            "Unknown cipher type: {}",
            cipher
        ))),
    };

    match result {
        Ok(encoded) => HttpResponse::Ok().json(serde_json::json!({
            "encoded": encoded,
            "cipher": cipher,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

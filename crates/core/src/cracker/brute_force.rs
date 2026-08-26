use crate::cracker::dictionary::{hex_eq_ignore_case, raw};
use crate::hash_id::{identify, HashType};
use serde::{Deserialize, Serialize};

const CHARSET_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const CHARSET_LOWER_DIGIT: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const CHARSET_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    pub hash: String,
    pub max_length: u8,
    pub charset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceResult {
    pub cracked: bool,
    pub plaintext: Option<String>,
    pub attempts: u64,
    pub method: String,
}

pub const MAX_ATTEMPTS: u64 = 20_000_000;

pub fn brute_force_crack(config: &BruteForceConfig) -> BruteForceResult {
    let charset_bytes: &[u8] = match config.charset.as_str() {
        "lower" => CHARSET_LOWER,
        "lowerdigit" => CHARSET_LOWER_DIGIT,
        "alnum" => CHARSET_ALNUM,
        _ => {
            return BruteForceResult {
                cracked: false,
                plaintext: None,
                attempts: 0,
                method: format!("brute-force (unknown charset {:?})", config.charset),
            }
        }
    };
    if charset_bytes.is_empty() {
        return BruteForceResult {
            cracked: false,
            plaintext: None,
            attempts: 0,
            method: "brute-force (empty charset)".to_string(),
        };
    }

    let trimmed = config.hash.trim().to_lowercase();
    let ident = identify(&config.hash);
    let ht = ident
        .first()
        .map(|i| i.hash_type.clone())
        .unwrap_or(HashType::Unknown);

    if !is_brute_forceable(&trimmed, &ht) {
        return BruteForceResult {
            cracked: false,
            plaintext: None,
            attempts: 0,
            method: "brute-force (skipped - hash too long or unsupported)".to_string(),
        };
    }

    type RawHasher = fn(&[u8]) -> Vec<u8>;
    let hasher: RawHasher = match ht {
        HashType::Md5 => |b| raw::md5(b).to_vec(),
        HashType::Sha1 => |b| raw::sha1(b).to_vec(),
        HashType::Sha256 => |b| raw::sha256(b).to_vec(),
        _ => {
            return BruteForceResult {
                cracked: false,
                plaintext: None,
                attempts: 0,
                method: "brute-force (unsupported hash type)".to_string(),
            }
        }
    };

    let mut total_attempts = 0u64;

    for len in 1..=usize::from(config.max_length) {
        let Some(candidate_count) = (charset_bytes.len() as u64).checked_pow(len as u32) else {
            break;
        };
        let budget = MAX_ATTEMPTS.saturating_sub(total_attempts);
        if budget == 0 {
            break;
        }
        let limit = candidate_count.min(budget);
        let mut indices = vec![0usize; len];
        let mut candidate = vec![0u8; len];

        for _ in 0..limit {
            for (slot, &i) in candidate.iter_mut().zip(indices.iter()) {
                *slot = charset_bytes[i];
            }
            total_attempts += 1;
            if hex_eq_ignore_case(&hasher(&candidate), trimmed.as_bytes()) {
                return BruteForceResult {
                    cracked: true,
                    plaintext: Some(String::from_utf8_lossy(&candidate).into_owned()),
                    attempts: total_attempts,
                    method: format!("brute-force (len={}, charset={})", len, config.charset),
                };
            }
            if !increment_indices(&mut indices, charset_bytes.len()) {
                break;
            }
        }
    }

    BruteForceResult {
        cracked: false,
        plaintext: None,
        attempts: total_attempts,
        method: "brute-force (exhausted)".to_string(),
    }
}

/// Outcome of a single [`BruteForceSession::step`] batch.
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    /// Batch completed; more work may remain — call `step` again.
    Continue,
    /// A preimage was found.
    Cracked,
    /// The keyspace or attempt budget is exhausted.
    Exhausted,
}

/// Incremental brute-force engine: runs the search in bounded batches so the
/// caller can report progress and stay responsive between batches (e.g. on the
/// browser main thread). Same enumeration order and budget as
/// [`brute_force_crack`], which is a convenience wrapper over this session.
pub struct BruteForceSession {
    hasher: fn(&[u8]) -> Vec<u8>,
    charset_bytes: &'static [u8],
    charset_name: String,
    target_hex: Vec<u8>,
    max_length: u8,
    len: usize,
    indices: Vec<usize>,
    /// Candidates remaining at the current length before advancing.
    remaining_at_len: u64,
    total_attempts: u64,
    found: Option<String>,
    done: bool,
}

impl BruteForceSession {
    pub fn new(config: &BruteForceConfig) -> Result<Self, String> {
        let charset_bytes: &'static [u8] = match config.charset.as_str() {
            "lower" => CHARSET_LOWER,
            "lowerdigit" => CHARSET_LOWER_DIGIT,
            "alnum" => CHARSET_ALNUM,
            _ => return Err(format!("unknown charset {:?}", config.charset)),
        };
        if charset_bytes.is_empty() {
            return Err("empty charset".to_string());
        }

        let trimmed = config.hash.trim().to_lowercase();
        let ident = identify(&config.hash);
        let ht = ident.first().map(|i| i.hash_type.clone());

        let hasher: fn(&[u8]) -> Vec<u8> = match &ht {
            Some(HashType::Md5) => |b| raw::md5(b).to_vec(),
            Some(HashType::Sha1) => |b| raw::sha1(b).to_vec(),
            Some(HashType::Sha256) => |b| raw::sha256(b).to_vec(),
            _ => {
                return Err("unsupported hash type for brute force".to_string());
            }
        };
        if !is_brute_forceable(&trimmed, ht.as_ref().unwrap()) {
            return Err("hash too long".to_string());
        }

        Ok(Self {
            hasher,
            charset_bytes,
            charset_name: config.charset.clone(),
            target_hex: trimmed.into_bytes(),
            max_length: config.max_length,
            len: 1,
            indices: vec![0; 1],
            remaining_at_len: charset_bytes.len() as u64,
            total_attempts: 0,
            found: None,
            done: false,
        })
    }

    pub fn attempts(&self) -> u64 {
        self.total_attempts
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Total candidates implied by the configured keyspace (may exceed the
    /// MAX_ATTEMPTS budget; progress should be reported against the budget).
    pub fn keyspace_size(&self) -> Option<u64> {
        let base = self.charset_bytes.len() as u64;
        let mut total: u64 = 0;
        for len in 1..=u32::from(self.max_length) {
            total = total.checked_add(base.checked_pow(len)?)?;
        }
        Some(total)
    }

    /// Runs up to `batch` additional attempts. Returns the current outcome;
    /// once `Cracked` or `Exhausted` is returned the session is finished and
    /// further calls are no-ops returning `Exhausted`.
    pub fn step(&mut self, batch: u32) -> StepOutcome {
        if self.done || batch == 0 {
            return StepOutcome::Exhausted;
        }
        let batch = batch as u64;
        let mut remaining = batch;
        while remaining > 0 {
            // Advance to the next non-exhausted length within limits.
            while self.remaining_at_len == 0 {
                self.len += 1;
                if self.len > usize::from(self.max_length)
                    || self.len > usize::try_from(MAX_ATTEMPTS).unwrap_or(usize::MAX)
                {
                    self.done = true;
                    return StepOutcome::Exhausted;
                }
                let count = (self.charset_bytes.len() as u64)
                    .checked_pow(self.len as u32)
                    .unwrap_or(0);
                self.indices = vec![0; self.len];
                self.remaining_at_len = count;
            }
            let budget = MAX_ATTEMPTS.saturating_sub(self.total_attempts);
            if budget == 0 {
                self.done = true;
                return StepOutcome::Exhausted;
            }

            let n = remaining.min(self.remaining_at_len).min(budget);
            let mut candidate = vec![0u8; self.len];
            for _ in 0..n {
                for (slot, &i) in candidate.iter_mut().zip(self.indices.iter()) {
                    *slot = self.charset_bytes[i];
                }
                self.total_attempts += 1;
                if hex_eq_ignore_case(&(self.hasher)(&candidate), &self.target_hex) {
                    self.done = true;
                    self.found = Some(String::from_utf8_lossy(&candidate).into_owned());
                    return StepOutcome::Cracked;
                }
                increment_indices(&mut self.indices, self.charset_bytes.len());
                self.remaining_at_len -= 1;
            }
            remaining -= n;
        }
        StepOutcome::Continue
    }

    /// The cracked plaintext; meaningful only after `step` returns `Cracked`.
    pub fn take_plaintext(&mut self) -> Option<String> {
        self.found.take()
    }

    /// Final [`BruteForceResult`] matching the wrapper's semantics.
    pub fn finish(&mut self, outcome: StepOutcome) -> BruteForceResult {
        self.done = true;
        match outcome {
            StepOutcome::Cracked => BruteForceResult {
                cracked: true,
                plaintext: self.found.take(),
                attempts: self.total_attempts,
                method: format!(
                    "brute-force (len={}, charset={})",
                    self.len, self.charset_name
                ),
            },
            _ => BruteForceResult {
                cracked: false,
                plaintext: None,
                attempts: self.total_attempts,
                method: "brute-force (exhausted)".to_string(),
            },
        }
    }
}

fn increment_indices(indices: &mut [usize], alphabet_size: usize) -> bool {
    for index in indices.iter_mut().rev() {
        *index += 1;
        if *index < alphabet_size {
            return true;
        }
        *index = 0;
    }
    false
}

fn is_brute_forceable(hash: &str, ht: &HashType) -> bool {
    match ht {
        HashType::Md5 | HashType::Sha1 | HashType::Sha256 => hash.len() <= 64,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cracker::dictionary::hash_md5;

    #[test]
    fn test_brute_force_md5_test() {
        let config = BruteForceConfig {
            hash: "098f6bcd4621d373cade4e832627b4f6".to_string(),
            max_length: 4,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(result.cracked);
        assert_eq!(result.plaintext.unwrap(), "test");
    }

    #[test]
    fn test_brute_force_md5_admin() {
        let config = BruteForceConfig {
            hash: "21232f297a57a5a743894a0e4a801fc3".to_string(),
            max_length: 5,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(result.cracked);
        assert_eq!(result.plaintext.unwrap(), "admin");
    }

    #[test]
    fn test_brute_force_not_found() {
        let config = BruteForceConfig {
            hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            max_length: 2,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(!result.cracked);
        assert_eq!(result.attempts, 702);
    }

    #[test]
    fn test_brute_force_unsupported_hash() {
        let config = BruteForceConfig {
            hash: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".to_string(),
            max_length: 2,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(!result.cracked);
        assert_eq!(
            result.method,
            "brute-force (skipped - hash too long or unsupported)"
        );
    }

    #[test]
    fn test_brute_force_unknown_charset_is_reported_not_silently_swapped() {
        // Previously an unknown charset silently fell back to lower+digit,
        // so a typo'd charset produced a misleading "(exhausted)" result.
        let config = BruteForceConfig {
            hash: hash_md5("test"),
            max_length: 4,
            charset: "lowerdigit ".trim().to_owned() + "x", // "lowerdigitx" — unknown
        };
        let result = brute_force_crack(&config);
        assert!(!result.cracked);
        assert_eq!(result.attempts, 0);
        assert_eq!(
            result.method,
            "brute-force (unknown charset \"lowerdigitx\")"
        );
    }

    #[test]
    fn test_brute_force_max_length_zero_attempts_nothing() {
        let config = BruteForceConfig {
            hash: hash_md5("test"),
            max_length: 0,
            charset: "lower".to_string(),
        };
        let result = brute_force_crack(&config);
        assert!(!result.cracked);
        assert_eq!(result.attempts, 0);
    }

    mod session_tests {
        use super::*;

        fn config(hash: &str, max_length: u8, charset: &str) -> BruteForceConfig {
            BruteForceConfig {
                hash: hash.to_string(),
                max_length,
                charset: charset.to_string(),
            }
        }

        #[test]
        fn session_finds_same_result_as_batch_run() {
            // Batched stepping must find the same preimage as one big batch.
            let target = config(&hash_md5("test"), 4, "lower");
            let mut a = BruteForceSession::new(&target).unwrap();
            loop {
                match a.step(7) {
                    StepOutcome::Continue => continue,
                    o => {
                        let r = a.finish(o);
                        assert!(r.cracked);
                        assert_eq!(r.plaintext.as_deref(), Some("test"));
                        break;
                    }
                }
            }

            let mut b = BruteForceSession::new(&target).unwrap();
            let outcome = b.step(u32::MAX / 2);
            let r = b.finish(outcome);
            assert!(r.cracked);
            // All candidates shorter than len 4 (26 + 676 + 17576) plus
            // "test"'s 1-based index within the len-4 keyspace.
            assert_eq!(r.attempts, 355_414);
        }

        #[test]
        fn session_rejects_bad_inputs() {
            assert!(BruteForceSession::new(&config("x", 3, "nope")).is_err());
            let sha512 = config(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                2, "lower",
            );
            assert!(BruteForceSession::new(&sha512).is_err());
        }

        #[test]
        fn session_step_after_done_is_exhausted() {
            let mut s = BruteForceSession::new(&config(&hash_md5("zzzzz"), 1, "lower")).unwrap();
            // Exhaust the single-letter keyspace: the last batch reports
            // Continue (budget remains, but keyspace is done on next step).
            let mut outcome = s.step(25);
            while outcome == StepOutcome::Continue {
                outcome = s.step(25);
            }
            assert_eq!(outcome, StepOutcome::Exhausted);
            assert!(s.is_done());
            // Further steps are no-ops.
            assert_eq!(s.step(10), StepOutcome::Exhausted);
            assert_eq!(s.attempts(), 26);
        }

        #[test]
        fn session_keyspace_size() {
            let s = BruteForceSession::new(&config(&hash_md5("a"), 2, "lower")).unwrap();
            assert_eq!(s.keyspace_size(), Some(26 + 26 * 26));
        }

        #[test]
        fn session_respects_attempt_budget() {
            // alnum^6 ≈ 56.8B candidates; budget caps at MAX_ATTEMPTS.
            let mut s =
                BruteForceSession::new(&config("00000000000000000000000000000000", 6, "alnum"))
                    .unwrap();
            let mut outcome = StepOutcome::Continue;
            while outcome == StepOutcome::Continue {
                outcome = s.step(1_000_000);
            }
            let r = s.finish(outcome);
            assert!(!r.cracked);
            assert_eq!(r.attempts, MAX_ATTEMPTS);
        }
    }
}

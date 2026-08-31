use serde::{Deserialize, Serialize};

/// Identifies the category of operation recorded in session history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    Identify,
    TextHash,
    HashComparison,
    CrackDictionary,
    CrackBruteForce,
    CipherTransform,
    CipherDetect,
    FileHash,
    FileCipher,
}

impl OperationType {
    /// Human-friendly name of the operation category.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Identify => "Hash Identification",
            Self::TextHash => "Text Hashing",
            Self::HashComparison => "Hash Comparison",
            Self::CrackDictionary => "Dictionary Crack",
            Self::CrackBruteForce => "Brute-force Crack",
            Self::CipherTransform => "Cipher Transform",
            Self::CipherDetect => "Cipher Detection",
            Self::FileHash => "File Hash",
            Self::FileCipher => "File Cipher",
        }
    }

    /// Short mnemonic code for tags and badges.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Identify => "ID",
            Self::TextHash => "HASH",
            Self::HashComparison => "CMP",
            Self::CrackDictionary => "DICT",
            Self::CrackBruteForce => "BRUTE",
            Self::CipherTransform => "CIPHER",
            Self::CipherDetect => "DETECT",
            Self::FileHash => "FILE-HASH",
            Self::FileCipher => "FILE-CIPHER",
        }
    }
}

/// A single immutable record of an operation conducted within the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: u64,
    pub timestamp_ms: u64,
    pub op_type: OperationType,
    pub title: String,
    pub summary: String,
    pub input_preview: String,
    pub output_preview: String,
    pub success: bool,
}

/// Parameters for recording a new operation in session history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewHistoryEntry {
    pub op_type: OperationType,
    pub title: String,
    pub summary: String,
    pub input_preview: String,
    pub output_preview: String,
    pub success: bool,
    pub timestamp_ms: u64,
}

impl NewHistoryEntry {
    /// Creates a new entry description for recording.
    #[must_use]
    pub fn new(
        op_type: OperationType,
        title: impl Into<String>,
        summary: impl Into<String>,
        input_preview: impl Into<String>,
        output_preview: impl Into<String>,
        success: bool,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            op_type,
            title: title.into(),
            summary: summary.into(),
            input_preview: input_preview.into(),
            output_preview: output_preview.into(),
            success,
            timestamp_ms,
        }
    }
}

/// Bounded, in-memory ephemeral session history store.
/// Zero persistence to storage or disk — when the browser tab closes, all data disappears.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHistory {
    entries: Vec<HistoryEntry>,
    max_entries: usize,
    next_id: u64,
}

impl Default for SessionHistory {
    fn default() -> Self {
        Self::new(100)
    }
}

impl SessionHistory {
    /// Create a new session history buffer with a maximum capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries: max_entries.max(1),
            next_id: 1,
        }
    }

    /// Record a new operation in session history. If the buffer is full, the oldest entry is dropped.
    pub fn record(&mut self, new_entry: NewHistoryEntry) -> &HistoryEntry {
        let entry = HistoryEntry {
            id: self.next_id,
            timestamp_ms: new_entry.timestamp_ms,
            op_type: new_entry.op_type,
            title: new_entry.title,
            summary: new_entry.summary,
            input_preview: new_entry.input_preview,
            output_preview: new_entry.output_preview,
            success: new_entry.success,
        };
        self.next_id = self.next_id.saturating_add(1);

        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
        self.entries.last().expect("entry was just inserted")
    }

    /// Returns a slice of all recorded entries in chronological order.
    #[must_use]
    pub fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }

    /// Returns a reverse-chronological iterator (newest first).
    pub fn iter_recent(&self) -> impl DoubleEndedIterator<Item = &HistoryEntry> {
        self.entries.iter().rev()
    }

    /// Returns the number of recorded operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no operations have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find an entry by its ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&HistoryEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Completely purge all session entries and reset IDs.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.next_id = 1;
    }

    /// Export the session history as a formatted JSON string.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }

    /// Export the session history as a structured Markdown audit log.
    #[must_use]
    pub fn export_markdown(&self) -> String {
        let mut md = String::from("# Devastator Session Audit Log\n\n");
        md.push_str("> Generated locally in browser. No remote logging or server telemetry.\n\n");
        md.push_str(&format!("Total Operations: **{}**\n\n---\n\n", self.len()));

        if self.is_empty() {
            md.push_str("*No operations recorded in this session.*\n");
            return md;
        }

        for entry in self.iter_recent() {
            let status = if entry.success {
                "✅ SUCCESS"
            } else {
                "⚠️ WARNING / FAILURE"
            };
            md.push_str(&format!(
                "### #{:03} [{}] {} ({})\n\n",
                entry.id,
                entry.op_type.tag(),
                entry.title,
                status
            ));
            md.push_str(&format!("- **Category**: {}\n", entry.op_type.label()));
            md.push_str(&format!("- **Summary**: {}\n", entry.summary));
            if !entry.input_preview.is_empty() {
                md.push_str(&format!(
                    "- **Input Preview**:\n```\n{}\n```\n",
                    entry.input_preview
                ));
            }
            if !entry.output_preview.is_empty() {
                md.push_str(&format!(
                    "- **Output Preview**:\n```\n{}\n```\n",
                    entry.output_preview
                ));
            }
            md.push_str("\n---\n\n");
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_history_basic_recording() {
        let mut history = SessionHistory::new(10);
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);

        history.record(NewHistoryEntry::new(
            OperationType::Identify,
            "MD5 Identification",
            "Identified as MD5 with high confidence",
            "5d41402abc4b2a76b9719d911017c592",
            "MD5 / NTLM",
            true,
            1_700_000_000_000,
        ));

        assert_eq!(history.len(), 1);
        assert!(!history.is_empty());
        let entry = history.get(1).expect("entry 1 should exist");
        assert_eq!(entry.id, 1);
        assert_eq!(entry.op_type, OperationType::Identify);
        assert_eq!(entry.title, "MD5 Identification");
        assert!(entry.success);
    }

    #[test]
    fn test_session_history_capacity_eviction() {
        let mut history = SessionHistory::new(3);

        for i in 1..=5 {
            history.record(NewHistoryEntry::new(
                OperationType::TextHash,
                format!("Hash operation #{i}"),
                format!("Computed SHA-256 for input #{i}"),
                format!("input_{i}"),
                format!("hash_{i}"),
                true,
                1_700_000_000_000 + i,
            ));
        }

        assert_eq!(history.len(), 3);
        assert!(history.get(1).is_none());
        assert!(history.get(2).is_none());
        assert!(history.get(3).is_some());
        assert!(history.get(4).is_some());
        assert!(history.get(5).is_some());

        let recent_ids: Vec<u64> = history.iter_recent().map(|e| e.id).collect();
        assert_eq!(recent_ids, vec![5, 4, 3]);
    }

    #[test]
    fn test_session_history_clear() {
        let mut history = SessionHistory::new(10);
        history.record(NewHistoryEntry::new(
            OperationType::CrackDictionary,
            "Cracked password",
            "Found 'hello'",
            "5d41402abc4b2a76b9719d911017c592",
            "hello",
            true,
            1_700_000_000_000,
        ));
        assert_eq!(history.len(), 1);

        history.clear();
        assert_eq!(history.len(), 0);
        assert!(history.is_empty());

        // Next record starts from id 1
        let entry = history.record(NewHistoryEntry::new(
            OperationType::FileHash,
            "Hashed file",
            "Computed 9 hashes",
            "test.bin",
            "sha256: ...",
            true,
            1_700_000_000_000,
        ));
        assert_eq!(entry.id, 1);
    }

    #[test]
    fn test_session_history_markdown_export() {
        let mut history = SessionHistory::new(5);
        history.record(NewHistoryEntry::new(
            OperationType::CipherTransform,
            "Base64 Encode",
            "Encoded 11 bytes to Base64",
            "hello world",
            "aGVsbG8gd29ybGQ=",
            true,
            1_700_000_000_000,
        ));

        let md = history.export_markdown();
        assert!(md.contains("# Devastator Session Audit Log"));
        assert!(md.contains("[CIPHER] Base64 Encode"));
        assert!(md.contains("aGVsbG8gd29ybGQ="));
    }
}

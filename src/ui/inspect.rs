//! Signature and hash checks on a background thread, like the C build's
//! file-information queue. Results are cached by path; the window reads them
//! when it rebuilds the list.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

use eframe::egui;

#[derive(Default)]
struct Results {
    /// Lowercase path to signer (None = not signed).
    signers: HashMap<String, Option<String>>,
    /// Lowercase path to SHA-256 (None = unreadable).
    hashes: HashMap<String, Option<String>>,
}

struct Request {
    path: String,
    signature: bool,
    hash: bool,
    revocation: bool,
}

pub struct Inspector {
    tx: Sender<Request>,
    results: Arc<Mutex<Results>>,
    /// Bumped by the worker after each result.
    version: Arc<AtomicU64>,
    seen: u64,
    asked_signature: HashSet<String>,
    asked_hash: HashSet<String>,
}

impl Inspector {
    pub fn spawn(ctx: egui::Context) -> Self {
        let (tx, rx) = channel::<Request>();
        let results = Arc::new(Mutex::new(Results::default()));
        let version = Arc::new(AtomicU64::new(0));
        let (out, bump) = (results.clone(), version.clone());
        std::thread::spawn(move || {
            while let Ok(request) = rx.recv() {
                let key = request.path.to_lowercase();
                if request.signature {
                    let signer = crate::security::signer(&request.path, request.revocation);
                    out.lock().unwrap().signers.insert(key.clone(), signer);
                }
                if request.hash {
                    let hash = crate::security::file_sha256(&request.path);
                    out.lock().unwrap().hashes.insert(key, hash);
                }
                bump.fetch_add(1, Ordering::Relaxed);
                ctx.request_repaint();
            }
        });
        Self {
            tx,
            results,
            version,
            seen: 0,
            asked_signature: HashSet::new(),
            asked_hash: HashSet::new(),
        }
    }

    /// Queue a signature check once per path.
    pub fn want_signature(&mut self, path: &str, revocation: bool) {
        if self.asked_signature.insert(path.to_lowercase()) {
            let _ = self.tx.send(Request { path: path.into(), signature: true, hash: false, revocation });
        }
    }

    /// Queue a hash. `fresh` asks again even if one was taken before.
    pub fn want_hash(&mut self, path: &str, fresh: bool) {
        let key = path.to_lowercase();
        if fresh {
            self.results.lock().unwrap().hashes.remove(&key);
        }
        if self.asked_hash.insert(key) || fresh {
            let _ = self.tx.send(Request { path: path.into(), signature: false, hash: true, revocation: false });
        }
    }

    /// True once per batch of new results.
    pub fn changed(&mut self) -> bool {
        let now = self.version.load(Ordering::Relaxed);
        let changed = now != self.seen;
        self.seen = now;
        changed
    }

    /// Signer for a path: outer None = not checked yet, inner None = not signed.
    pub fn signer(&self, path: &str) -> Option<Option<String>> {
        self.results.lock().unwrap().signers.get(&path.to_lowercase()).cloned()
    }

    pub fn signers(&self) -> HashMap<String, Option<String>> {
        self.results.lock().unwrap().signers.clone()
    }

    pub fn hash(&self, path: &str) -> Option<Option<String>> {
        self.results.lock().unwrap().hashes.get(&path.to_lowercase()).cloned()
    }

    /// Forget signatures, after the revocation setting changes.
    pub fn reset_signatures(&mut self) {
        self.asked_signature.clear();
        self.results.lock().unwrap().signers.clear();
    }
}

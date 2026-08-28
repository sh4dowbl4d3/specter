use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use devastator_core::cipher_tools::ciphers::*;
use devastator_core::cipher_tools::detect_cipher;
use devastator_core::cracker::brute_force::*;
use devastator_core::cracker::dictionary::*;
use devastator_core::hash_id::*;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::*;

const MAX_FILE_BYTES: f64 = 64.0 * 1024.0 * 1024.0;

thread_local! {
    static WORDLIST: RefCell<Option<String>> = const { RefCell::new(None) };
    static CIPHER_FILE_CONTENT: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
    static FI_FILE: RefCell<Option<File>> = const { RefCell::new(None) };
    static FCI_FILE: RefCell<Option<File>> = const { RefCell::new(None) };
}

#[wasm_bindgen(start)]
fn start() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    // Avoid restoring a stale scroll position that can reopen the app on the footer.
    let current_url = window()
        .unwrap()
        .document()
        .unwrap()
        .url()
        .unwrap_or_default();
    if !current_url.contains('#') {
        window().unwrap().scroll_to_with_x_and_y(0.0, 0.0);
    }
    setup_tabs();
    setup_ci_type_change();
    setup_copy_buttons();
    setup_keyboard_shortcuts();
    setup_hash_identify();
    setup_text_hashing();
    setup_hash_comparison();
    setup_crack();
    setup_cipher_tools();
    setup_file_tools();
    Ok(())
}

fn el(id: &str) -> Element {
    window()
        .unwrap()
        .document()
        .unwrap()
        .get_element_by_id(id)
        .unwrap_or_else(|| panic!("#{id} not found"))
}

fn val(id: &str) -> String {
    let e = el(id);
    if let Ok(input) = e.clone().dyn_into::<HtmlInputElement>() {
        return input.value();
    }
    if let Ok(textarea) = e.dyn_into::<HtmlTextAreaElement>() {
        return textarea.value();
    }
    String::new()
}

fn text(id: &str, t: &str) {
    el(id).set_text_content(Some(t));
}

fn class_list(id: &str) -> DomTokenList {
    el(id).unchecked_into::<HtmlElement>().class_list()
}

fn show(id: &str) {
    class_list(id).remove_1("hidden").unwrap();
}

fn hide(id: &str) {
    class_list(id).add_1("hidden").unwrap();
}

fn add_vis_class(id: &str, c: &str) {
    class_list(id).add_1(c).unwrap();
}

fn remove_vis_class(id: &str, c: &str) {
    class_list(id).remove_1(c).unwrap();
}

fn toast(msg: &str) {
    let t = el("toast").unchecked_into::<HtmlElement>();
    t.set_text_content(Some(msg));
    t.class_list().remove_1("error").unwrap();
    t.class_list().add_1("show").unwrap();
    let t2 = el("toast").unchecked_into::<HtmlElement>();
    let cb = Closure::once(move || {
        t2.class_list().remove_1("show").unwrap();
    });
    window()
        .unwrap()
        .set_timeout_with_callback_and_timeout_and_arguments_0(cb.as_ref().unchecked_ref(), 2200)
        .unwrap();
    cb.forget();
}

fn toast_error(msg: &str) {
    let t = el("toast").unchecked_into::<HtmlElement>();
    t.set_text_content(Some(msg));
    t.class_list().add_1("error").unwrap();
    t.class_list().add_1("show").unwrap();
    let t2 = el("toast").unchecked_into::<HtmlElement>();
    let cb = Closure::once(move || {
        t2.class_list().remove_1("show").unwrap();
    });
    window()
        .unwrap()
        .set_timeout_with_callback_and_timeout_and_arguments_0(cb.as_ref().unchecked_ref(), 3200)
        .unwrap();
    cb.forget();
}

fn copy_text(text: &str) {
    let c = window().unwrap().navigator().clipboard();
    let p = c.write_text(text);
    let fut = JsFuture::from(p);
    spawn_local(async move {
        match fut.await {
            Ok(_) => toast("Copied"),
            Err(e) => toast_error(&format!("Clipboard error: {:?}", e)),
        }
    });
}

fn show_progress(id_prefix: &str) {
    show(&format!("{id_prefix}-progress"));
    add_vis_class(&format!("{id_prefix}-progress"), "active");
    text(&format!("{id_prefix}-progress-text"), "Processing...");
}

fn hide_progress(id_prefix: &str) {
    remove_vis_class(&format!("{id_prefix}-progress"), "active");
    hide(&format!("{id_prefix}-progress"));
}

fn download_file(name: &str, content: &str) {
    let doc = window().unwrap().document().unwrap();
    let blob = Blob::new_with_str_sequence(&JsValue::from_str(content)).unwrap();
    let url = Url::create_object_url_with_blob(&blob).unwrap();
    let anchor = doc
        .create_element("a")
        .unwrap()
        .unchecked_into::<HtmlAnchorElement>();
    anchor.set_href(&url);
    anchor.set_download(name);
    anchor.style().set_property("display", "none").unwrap();
    doc.body().unwrap().append_child(&anchor).unwrap();
    anchor.click();
    doc.body().unwrap().remove_child(&anchor).unwrap();
    Url::revoke_object_url(&url).unwrap();
}

fn click_handler(id: &str, cb: impl FnMut() + 'static) {
    let cb = Closure::wrap(Box::new(cb) as Box<dyn FnMut()>);
    el(id)
        .unchecked_into::<HtmlButtonElement>()
        .set_onclick(Some(cb.as_ref().unchecked_ref()));
    cb.forget();
}

fn file_read_handler(
    file: File,
    on_loaded: impl Fn(String) + 'static,
    on_error: impl Fn(String) + 'static,
) {
    if file.size() > MAX_FILE_BYTES {
        on_error("File exceeds the 64 MiB limit".to_string());
        return;
    }
    let fut = JsFuture::from(file.text());
    spawn_local(async move {
        match fut.await {
            Ok(val) => on_loaded(val.as_string().unwrap_or_default()),
            Err(e) => on_error(format!("{:?}", e)),
        }
    });
}

fn file_read_binary_handler(
    file: File,
    on_loaded: impl Fn(Vec<u8>) + 'static,
    on_error: impl Fn(String) + 'static,
) {
    if file.size() > MAX_FILE_BYTES {
        on_error("File exceeds the 64 MiB limit".to_string());
        return;
    }
    let fut = JsFuture::from(file.array_buffer());
    spawn_local(async move {
        match fut.await {
            Ok(val) => {
                let buf = Uint8Array::new(&val);
                let mut bytes = vec![0; buf.length() as usize];
                buf.copy_to(&mut bytes);
                on_loaded(bytes);
            }
            Err(e) => on_error(format!("{:?}", e)),
        }
    });
}

fn setup_file_dropzone(
    dropzone_id: &str,
    file_input_id: &str,
    drop_text_id: &str,
    on_file: impl Fn(File) + Clone + 'static,
) {
    let dz = el(dropzone_id).unchecked_into::<HtmlElement>();
    let dz2 = dz.clone();

    let over = Closure::wrap(Box::new(move |e: DragEvent| {
        e.prevent_default();
        dz.class_list().add_1("dragover").unwrap();
    }) as Box<dyn FnMut(_)>);
    dz2.add_event_listener_with_callback("dragover", over.as_ref().unchecked_ref())
        .unwrap();
    over.forget();

    let dz3 = dz2.clone();
    let leave = Closure::wrap(Box::new(move |_e: DragEvent| {
        dz3.class_list().remove_1("dragover").unwrap();
    }) as Box<dyn FnMut(_)>);
    dz2.add_event_listener_with_callback("dragleave", leave.as_ref().unchecked_ref())
        .unwrap();
    leave.forget();

    let dz4 = dz2.clone();
    let dt = drop_text_id.to_string();
    let on_file_clone = on_file.clone();
    let drop = Closure::wrap(Box::new(move |e: DragEvent| {
        e.prevent_default();
        dz4.class_list().remove_1("dragover").unwrap();
        if let Some(dt2) = e.data_transfer() {
            if let Some(file) = dt2.files().and_then(|fl| fl.item(0)) {
                el(&dt).set_text_content(Some(&file.name()));
                on_file_clone(file);
            }
        }
    }) as Box<dyn FnMut(_)>);
    dz2.add_event_listener_with_callback("drop", drop.as_ref().unchecked_ref())
        .unwrap();
    drop.forget();

    let fi = file_input_id.to_string();
    let dt2 = drop_text_id.to_string();
    let file_cb = Closure::wrap(Box::new(move || {
        if let Some(file) = el(&fi)
            .unchecked_into::<HtmlInputElement>()
            .files()
            .and_then(|fl| fl.item(0))
        {
            el(&dt2).set_text_content(Some(&file.name()));
            on_file(file);
        }
    }) as Box<dyn FnMut()>);
    el(file_input_id)
        .unchecked_into::<HtmlInputElement>()
        .set_onchange(Some(file_cb.as_ref().unchecked_ref()));
    file_cb.forget();
}

// ── Tab switching ─────────────────────────────────────────────

fn setup_tabs() {
    let tabs = el("tabs").unchecked_into::<HtmlElement>();
    let tabs_handle = tabs.clone();
    let panels: [&str; 4] = ["tab-identify", "tab-crack", "tab-ciphers", "tab-files"];

    let cb = Closure::wrap(Box::new(move |e: MouseEvent| {
        let target = match e.target() {
            Some(t) => t,
            None => return,
        };
        let btn = if let Some(b) = target.dyn_ref::<HtmlButtonElement>() {
            b.clone()
        } else if let Some(elt) = target.dyn_ref::<Element>() {
            match elt.closest("button") {
                Ok(Some(b)) => b.unchecked_into::<HtmlButtonElement>(),
                _ => return,
            }
        } else {
            return;
        };
        let tab = match btn.get_attribute("data-tab") {
            Some(t) => t,
            None => return,
        };

        if let Ok(buttons) = tabs.query_selector_all("button") {
            for i in 0..buttons.length() {
                if let Some(node) = buttons.item(i) {
                    let el = node.unchecked_into::<HtmlElement>();
                    el.class_list().remove_1("active").unwrap();
                    el.set_attribute("aria-selected", "false").unwrap();
                }
            }
        }
        btn.clone()
            .unchecked_into::<HtmlElement>()
            .class_list()
            .add_1("active")
            .unwrap();
        btn.set_attribute("aria-selected", "true").unwrap();

        for p in &panels {
            if *p == format!("tab-{tab}") {
                show(p);
                el(p).set_attribute("aria-hidden", "false").unwrap();
            } else {
                hide(p);
                el(p).set_attribute("aria-hidden", "true").unwrap();
            }
        }
    }) as Box<dyn FnMut(MouseEvent)>);

    tabs_handle.set_onclick(Some(cb.as_ref().unchecked_ref()));
    cb.forget();
}

// ── Global events ─────────────────────────────────────────────

fn setup_ci_type_change() {
    let cb = Closure::wrap(Box::new(move || {
        let v = val("ci-type");
        match v.as_str() {
            "caesar" | "vigenere" => show("ci-param-group"),
            _ => hide("ci-param-group"),
        }
    }) as Box<dyn FnMut()>);
    el("ci-type")
        .unchecked_into::<HtmlSelectElement>()
        .set_onchange(Some(cb.as_ref().unchecked_ref()));
    cb.forget();
}

fn setup_copy_buttons() {
    let pairs = [
        ("id-output", "id-output-body"),
        ("th-output", "th-output-body"),
        ("cmp-output", "cmp-output-body"),
        ("cr-output", "cr-output-body"),
        ("ci-output", "ci-output-body"),
        ("fi-output", "fi-output-body"),
        ("fci-output", "fci-output-body"),
    ];
    for (container_id, body_id) in &pairs {
        let bid = body_id.to_string();
        if let Ok(Some(btn)) = el(container_id).query_selector(".cpy") {
            let cb = Closure::wrap(Box::new(move || {
                let body_text = el(&bid).text_content().unwrap_or_default();
                if !body_text.trim().is_empty() {
                    copy_text(&body_text);
                }
            }) as Box<dyn FnMut()>);
            btn.unchecked_into::<HtmlButtonElement>()
                .set_onclick(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }
    }
}

fn setup_keyboard_shortcuts() {
    let id_input = el("id-hash-input").dyn_into::<HtmlTextAreaElement>().ok();
    if let Some(textarea) = id_input {
        let cb = Closure::wrap(Box::new(move |e: KeyboardEvent| {
            if e.key() == "Enter" && (e.ctrl_key() || e.meta_key()) {
                el("id-btn").unchecked_into::<HtmlButtonElement>().click();
            }
        }) as Box<dyn FnMut(_)>);
        textarea.set_onkeydown(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    let ci_input = el("ci-text").dyn_into::<HtmlTextAreaElement>().ok();
    if let Some(textarea) = ci_input {
        let cb = Closure::wrap(Box::new(move |e: KeyboardEvent| {
            if e.key() == "Enter" && (e.ctrl_key() || e.meta_key()) {
                el("ci-btn-decode")
                    .unchecked_into::<HtmlButtonElement>()
                    .click();
            }
        }) as Box<dyn FnMut(_)>);
        textarea.set_onkeydown(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }
}

// ── Hash identify ─────────────────────────────────────────────

fn setup_hash_identify() {
    click_handler("id-btn", || {
        let input = val("id-hash-input");
        if input.trim().is_empty() {
            text("id-output-body", "Enter a hash first");
            return;
        }
        let results = identify(&input);
        let json = serde_json::to_string_pretty(&results)
            .unwrap_or_else(|_| "Serialize error".to_string());
        text("id-output-body", &json);
    });
}

fn setup_text_hashing() {
    click_handler("th-btn-hash", || {
        let input = val("th-text-input");
        if input.is_empty() {
            text("th-output-body", "Enter text to hash first");
            return;
        }
        let algo_id = val("th-algo");
        if algo_id == "all" {
            let res = devastator_core::hasher::compute_all_hashes_text(&input);
            let json = serde_json::to_string_pretty(&res).unwrap_or_default();
            text("th-output-body", &json);
        } else {
            let algo = devastator_core::hasher::HashAlgorithm::from_id(&algo_id)
                .unwrap_or(devastator_core::hasher::HashAlgorithm::Sha256);
            let res = devastator_core::hasher::compute_hash_text(algo, &input);
            let json = serde_json::to_string_pretty(&res).unwrap_or_default();
            text("th-output-body", &json);
        }
    });

    click_handler("th-btn-multi", || {
        let input = val("th-text-input");
        if input.is_empty() {
            text("th-output-body", "Enter text to hash first");
            return;
        }
        let res = devastator_core::hasher::compute_all_hashes_text(&input);
        let json = serde_json::to_string_pretty(&res).unwrap_or_default();
        text("th-output-body", &json);
    });
}

fn setup_hash_comparison() {
    click_handler("cmp-btn-compare", || {
        let a = val("cmp-hash-a");
        let b = val("cmp-hash-b");
        if a.trim().is_empty() || b.trim().is_empty() {
            text("cmp-output-body", "Enter two hashes to compare.");
            return;
        }
        let res = devastator_core::hasher::compare_hashes(&a, &b);
        let json = serde_json::to_string_pretty(&res).unwrap_or_default();
        text("cmp-output-body", &json);
    });

    click_handler("cmp-btn-clear", || {
        if let Ok(input) = el("cmp-hash-a").dyn_into::<HtmlTextAreaElement>() {
            input.set_value("");
        }
        if let Ok(input) = el("cmp-hash-b").dyn_into::<HtmlTextAreaElement>() {
            input.set_value("");
        }
        text("cmp-output-body", "Enter two hashes and click Compare.");
    });
}

// ── Crack tab ─────────────────────────────────────────────────

fn setup_crack() {
    setup_file_dropzone("cr-dropzone", "cr-file-input", "cr-drop-text", |file| {
        file_read_handler(
            file,
            |content| {
                let line_count = content.lines().filter(|l| !l.trim().is_empty()).count();
                WORDLIST.with(|wl| *wl.borrow_mut() = Some(content));
                text("cr-drop-text", &format!("Loaded {line_count} words"));
            },
            |e| toast_error(&format!("Failed to read file: {e}")),
        );
    });

    click_handler("cr-btn-dict", || {
        let hash = val("cr-hash-input");
        if hash.trim().is_empty() {
            text("cr-output-body", "Enter a hash first");
            return;
        }
        let pasted = val("cr-wordlist-text");
        if !pasted.trim().is_empty() {
            let result = crack_from_list(&hash, &pasted);
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            text("cr-output-body", &json);
            return;
        }
        let wordlist = WORDLIST.with(|wl| wl.borrow().clone());
        match wordlist {
            Some(wl) => {
                let result = crack_from_list(&hash, &wl);
                let json = serde_json::to_string_pretty(&result).unwrap_or_default();
                text("cr-output-body", &json);
            }
            None => text("cr-output-body", "Upload or paste a wordlist first"),
        }
    });

    click_handler("cr-btn-bf", || {
        // A click while a run is active means "cancel".
        let active = CRACK_RUN.with(|r| r.borrow().is_some());
        if active {
            CRACK_RUN.with(|r| *r.borrow_mut() = None);
            return;
        }

        let hash = val("cr-hash-input");
        if hash.trim().is_empty() {
            text("cr-output-body", "Enter a hash first");
            return;
        }
        let max_len: u8 = val("cr-bf-maxlen").parse().unwrap_or(4);
        let charset = val("cr-bf-charset");
        let config = BruteForceConfig {
            hash: hash.clone(),
            max_length: max_len,
            charset,
        };
        let session = match BruteForceSession::new(&config) {
            Ok(s) => s,
            Err(e) => {
                text("cr-output-body", &format!("Brute-force unavailable: {e}"));
                toast_error(&format!("Cannot start brute-force: {e}"));
                return;
            }
        };

        // Run identity: only the newest run may write output or UI state.
        let run_id = next_run_id();
        CRACK_RUN.with(|r| *r.borrow_mut() = Some(run_id));

        let total = session.keyspace_size().unwrap_or(0).min(MAX_ATTEMPTS);
        text(
            "cr-progress-text",
            &format!("Cracking — 0 / {}", format_count(total)),
        );
        show_progress("cr");
        set_bf_button_label("Cancel");

        let cell: Rc<RefCell<Option<BruteForceSession>>> = Rc::new(RefCell::new(Some(session)));
        schedule_cracking_step(run_id, cell, total);
    });
}

/// Runs one batch of the cracking session, updates progress, and re-schedules
/// itself via `setTimeout(0)` so the browser can paint between batches.
/// Cancels cleanly when the run id is superseded or cleared.
fn schedule_cracking_step(run_id: u64, cell: Rc<RefCell<Option<BruteForceSession>>>, total: u64) {
    spawn_local(async move {
        // Stale run (superseded by a newer one, or cancelled): drop state.
        if CRACK_RUN.with(|r| *r.borrow()) != Some(run_id) {
            cell.borrow_mut().take();
            return;
        }

        const BATCH: u32 = 250_000;
        let outcome = match cell.borrow_mut().as_mut() {
            Some(session) => session.step(BATCH),
            None => StepOutcome::Exhausted,
        };
        let attempts = cell.borrow().as_ref().map(|s| s.attempts()).unwrap_or(0);

        match outcome {
            StepOutcome::Continue => {
                text(
                    "cr-progress-text",
                    &format!(
                        "Cracking — {} / {} ({:.0}%)",
                        format_count(attempts),
                        format_count(total),
                        if total > 0 {
                            attempts as f64 / total as f64 * 100.0
                        } else {
                            100.0
                        }
                    ),
                );
                let next_cell = cell.clone();
                let cb = Closure::once(move || {
                    schedule_cracking_step(run_id, next_cell, total);
                });
                window()
                    .unwrap()
                    .set_timeout_with_callback_and_timeout_and_arguments_0(
                        cb.as_ref().unchecked_ref(),
                        0,
                    )
                    .ok();
                cb.forget();
            }
            StepOutcome::Cracked => {
                let result = finish_session(&cell, StepOutcome::Cracked);
                end_run(Some(run_id));
                hide_progress("cr");
                let json = serde_json::to_string_pretty(&result).unwrap_or_default();
                text("cr-output-body", &json);
                toast(&format!(
                    "Cracked: {}",
                    result.plaintext.as_deref().unwrap_or("?")
                ));
            }
            StepOutcome::Exhausted => {
                let cancelled = CRACK_RUN.with(|r| r.borrow().is_none());
                if !cancelled {
                    let result = finish_session(&cell, StepOutcome::Exhausted);
                    end_run(Some(run_id));
                    let json = serde_json::to_string_pretty(&result).unwrap_or_default();
                    text("cr-output-body", &json);
                    toast(&format!(
                        "Not found after {} attempts",
                        format_count(result.attempts)
                    ));
                } else {
                    // User-initiated cancel: discard silently.
                    cell.borrow_mut().take();
                    end_run(Some(run_id));
                }
                hide_progress("cr");
            }
        }
    });
}

fn finish_session(
    cell: &Rc<RefCell<Option<BruteForceSession>>>,
    outcome: StepOutcome,
) -> BruteForceResult {
    cell.borrow_mut()
        .take()
        .map(|mut s| s.finish(outcome))
        .unwrap_or(BruteForceResult {
            cracked: false,
            plaintext: None,
            attempts: 0,
            method: "brute-force (cancelled)".to_string(),
        })
}

thread_local! {
    /// Identity of the active crack run. Set to `None` to cancel; stale async
    /// tasks notice and bail out without writing output.
    static CRACK_RUN: RefCell<Option<u64>> = const { RefCell::new(None) };
}

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

fn next_run_id() -> u64 {
    NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed)
}

/// Ends the current run (if `run_id` matches) and resets the button label.
fn end_run(run_id: Option<u64>) {
    CRACK_RUN.with(|r| {
        if run_id.is_none() || *r.borrow() == run_id {
            *r.borrow_mut() = None;
        }
    });
    set_bf_button_label("Brute-force");
}

fn set_bf_button_label(label: &str) {
    el("cr-btn-bf").set_text_content(Some(label));
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn valid_vigenere_key(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|character| character.is_ascii_alphabetic())
}

// ── Cipher tools ──────────────────────────────────────────────

fn cipher_encode(input: &str, cipher: &str, param: &str) -> Result<String, String> {
    match cipher {
        "base64" => Ok(base64_encode(input)),
        "hex" => Ok(hex_encode(input)),
        "binary" => Ok(binary_encode(input)),
        "rot13" => Ok(rot13(input)),
        "atbash" => Ok(atbash(input)),
        "caesar" => {
            let shift = param.parse::<u8>().unwrap_or(0);
            Ok(caesar_encrypt(input, shift))
        }
        "vigenere" => {
            if !valid_vigenere_key(param) {
                Err("Vigenère key must contain ASCII letters".to_string())
            } else {
                Ok(vigenere_encrypt(input, param))
            }
        }
        _ => Err(format!("Unknown cipher: {cipher}")),
    }
}

fn cipher_decode(input: &str, cipher: &str, param: &str) -> Result<String, String> {
    match cipher {
        "base64" => base64_decode(input).map_err(|e| e.to_string()),
        "hex" => hex_decode(input).map_err(|e| e.to_string()),
        "binary" => binary_decode(input).map_err(|e| e.to_string()),
        "rot13" => Ok(rot13(input)),
        "atbash" => Ok(atbash(input)),
        "caesar" => {
            let shift = param.parse::<u8>().unwrap_or(0);
            Ok(caesar_decrypt(input, shift))
        }
        "vigenere" => {
            if !valid_vigenere_key(param) {
                Err("Vigenère key must contain ASCII letters".to_string())
            } else {
                Ok(vigenere_decrypt(input, param))
            }
        }
        _ => Err(format!("Unknown cipher: {cipher}")),
    }
}

fn setup_cipher_tools() {
    click_handler("ci-btn-encode", || {
        let input = val("ci-text");
        if input.trim().is_empty() {
            text("ci-output-body", "Enter text first");
            return;
        }
        let cipher = val("ci-type");
        if cipher == "auto" {
            text("ci-output-body", "Select a specific cipher for encoding");
            return;
        }
        let param = val("ci-param");
        match cipher_encode(&input, &cipher, &param) {
            Ok(encoded) => {
                let out = serde_json::to_string_pretty(&serde_json::json!({
                    "encoded": encoded,
                    "cipher": cipher,
                }))
                .unwrap_or_default();
                text("ci-output-body", &out);
            }
            Err(e) => text("ci-output-body", &format!("Error: {e}")),
        }
    });

    click_handler("ci-btn-decode", || {
        let input = val("ci-text");
        if input.trim().is_empty() {
            text("ci-output-body", "Enter text first");
            return;
        }
        let cipher = val("ci-type");
        if cipher == "auto" {
            let detections = detect_cipher(&input);
            let json = serde_json::to_string_pretty(&detections).unwrap_or_default();
            text("ci-output-body", &json);
            return;
        }
        let param = val("ci-param");
        match cipher_decode(&input, &cipher, &param) {
            Ok(decoded) => {
                let out = serde_json::to_string_pretty(&serde_json::json!({
                    "decoded": decoded,
                    "cipher": cipher,
                }))
                .unwrap_or_default();
                text("ci-output-body", &out);
            }
            Err(e) => text("ci-output-body", &format!("Error: {e}")),
        }
    });

    click_handler("ci-btn-detect", || {
        let input = val("ci-text");
        if input.trim().is_empty() {
            text("ci-output-body", "Enter text first");
            return;
        }
        let detections = detect_cipher(&input);
        let json = serde_json::to_string_pretty(&detections).unwrap_or_default();
        text("ci-output-body", &json);
    });
}

// ── File tools ────────────────────────────────────────────────

fn setup_file_tools() {
    setup_file_dropzone("fi-dropzone", "fi-file-input", "fi-drop-text", |file| {
        FI_FILE.with(|f| *f.borrow_mut() = Some(file));
    });

    click_handler("fi-btn-hash", || {
        let file = FI_FILE.with(|f| f.borrow().clone());
        match file {
            None => text("fi-output-body", "Upload a file first"),
            Some(f) => {
                show_progress("fi");
                let algo = val("fi-algo");
                file_read_binary_handler(
                    f,
                    move |bytes| {
                        let out = if algo == "all" {
                            let digests = devastator_core::hasher::compute_all_hashes(&bytes);
                            serde_json::to_string_pretty(&serde_json::json!({
                                "mode": "multi-hash",
                                "byte_length": bytes.len(),
                                "digests": digests,
                            }))
                            .unwrap_or_default()
                        } else {
                            let hash_algo = devastator_core::hasher::HashAlgorithm::from_id(&algo)
                                .unwrap_or(devastator_core::hasher::HashAlgorithm::Sha256);
                            let hash = devastator_core::hasher::compute_hash(hash_algo, &bytes);
                            serde_json::to_string_pretty(&serde_json::json!({
                                "algorithm": hash_algo.name(),
                                "algorithm_id": hash_algo.id_str(),
                                "hash": hash,
                            }))
                            .unwrap_or_default()
                        };
                        hide_progress("fi");
                        text("fi-output-body", &out);
                    },
                    |e| {
                        hide_progress("fi");
                        text("fi-output-body", &format!("Error reading file: {e}"));
                    },
                );
            }
        }
    });

    setup_file_dropzone("fci-dropzone", "fci-file-input", "fci-drop-text", |file| {
        FCI_FILE.with(|f| *f.borrow_mut() = Some(file));
    });

    click_handler("fci-btn-encode", || {
        let file = FCI_FILE.with(|f| f.borrow().clone());
        match file {
            None => text("fci-output-body", "Upload a file first"),
            Some(f) => {
                show_progress("fci");
                let cipher = val("fci-type");
                file_read_handler(
                    f,
                    move |content| {
                        let result = match cipher.as_str() {
                            "base64" => base64_encode(&content),
                            "hex" => hex_encode(&content),
                            "rot13" => rot13(&content),
                            "atbash" => atbash(&content),
                            _ => "Unknown cipher".to_string(),
                        };
                        CIPHER_FILE_CONTENT
                            .with(|st| *st.borrow_mut() = Some((cipher.clone(), result.clone())));
                        text("fci-output-body", &result);
                        hide_progress("fci");
                        show("fci-btn-download");
                    },
                    |e| {
                        hide_progress("fci");
                        text("fci-output-body", &format!("Error: {e}"));
                    },
                );
            }
        }
    });

    click_handler("fci-btn-decode", || {
        let file = FCI_FILE.with(|f| f.borrow().clone());
        match file {
            None => text("fci-output-body", "Upload a file first"),
            Some(f) => {
                show_progress("fci");
                let cipher = val("fci-type");
                file_read_handler(
                    f,
                    move |content| {
                        let result = match cipher.as_str() {
                            "base64" => base64_decode(&content).map_err(|e| e.to_string()),
                            "hex" => hex_decode(&content).map_err(|e| e.to_string()),
                            "rot13" => Ok(rot13(&content)),
                            "atbash" => Ok(atbash(&content)),
                            _ => Err("Unknown cipher".to_string()),
                        };
                        match result {
                            Ok(decoded) => {
                                CIPHER_FILE_CONTENT.with(|st| {
                                    *st.borrow_mut() = Some((cipher.clone(), decoded.clone()))
                                });
                                text("fci-output-body", &decoded);
                                hide_progress("fci");
                                show("fci-btn-download");
                            }
                            Err(e) => {
                                hide_progress("fci");
                                text("fci-output-body", &format!("Error: {e}"));
                            }
                        }
                    },
                    |e| {
                        hide_progress("fci");
                        text("fci-output-body", &format!("Error: {e}"));
                    },
                );
            }
        }
    });

    click_handler("fci-btn-download", || {
        CIPHER_FILE_CONTENT.with(|st| {
            let data = st.borrow().clone();
            if let Some((cipher, content)) = data {
                let ext = match cipher.as_str() {
                    "base64" => "b64",
                    "hex" => "hex",
                    _ => "txt",
                };
                download_file(&format!("output.{ext}"), &content);
                toast("Downloaded");
            }
        });
    });
}

use std::{
    cell::RefCell,
    io::Read,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use slint_keyos_platform::{
    gui_server_api::navigation::filepicker::{
        AllowedExtensions, AllowedLocations, Location, SelectFileOptions,
    },
    navigation::select_file,
    sleep,
    slint::{ComponentHandle, ModelRc, VecModel},
    spawn_local, spawn_worker,
};
use verify_core::trust::TrustStore;
use verify_core::{
    digest_matches, encode_hex, find_manifest_entry, parse_expected_digest, parse_manifest,
    verify_detached_signature, HashAlgorithm, SignatureIdentity, MAX_MANIFEST_BYTES,
    MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES,
};

use crate::{gui_permissions::GuiPermissions, Actions, AppWindow, SavedPublisher, VerifyState};

fs::use_api!();
crypto::use_api!();

const TRUST_FILE: &str = "trusted-publishers.txt";
const TRUSTED_KEY_PREFIX: &str = "trusted-publisher-";

#[derive(Clone)]
struct SelectedFile {
    path: String,
    location: fs::Location,
}

#[derive(Clone)]
struct PendingTrust {
    identity: SignatureIdentity,
    key_bytes: Vec<u8>,
}

#[derive(Clone)]
enum ChecksumSource {
    File(SelectedFile),
    Digest(Vec<u8>),
}

impl SelectedFile {
    fn name(&self) -> &str {
        self.path.rsplit(['/', '\\']).next().unwrap_or(&self.path)
    }
}

#[derive(Default)]
struct State {
    compare_artifact: Option<SelectedFile>,
    compare_checksums: Option<ChecksumSource>,
    release_artifact: Option<SelectedFile>,
    release_manifest: Option<SelectedFile>,
    release_signature: Option<SelectedFile>,
    release_key: Option<SelectedFile>,
    trusted: TrustStore,
    pending_trust: Option<PendingTrust>,
    job_serial: u64,
    job: Option<Job>,
}

#[derive(Clone, Default)]
struct Job {
    cancelled: Arc<AtomicBool>,
    kib_processed: Arc<AtomicU32>,
}

pub fn init(ui: &AppWindow) {
    let state = Rc::new(RefCell::new(State {
        trusted: load_trusted_keys(),
        ..State::default()
    }));
    let actions = ui.global::<Actions>();
    push_trusted_keys(ui, &state.borrow().trusted);

    actions.on_hash_file({
        let weak = ui.as_weak();
        let state = state.clone();
        move |sha512| {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            clear_error(&ui);
            let selected = match pick_file() {
                Ok(Some(file)) => file,
                Ok(None) => return false,
                Err(error) => return fail(&ui, &error),
            };
            state.borrow_mut().compare_artifact = Some(selected.clone());
            ui.global::<VerifyState>()
                .set_compare_artifact(display_name(selected.name()).into());
            let (serial, job) = begin_job(&ui, &state);
            let weak = ui.as_weak();
            let state = state.clone();
            let name = display_name(selected.name());
            let algorithm = if sha512 {
                HashAlgorithm::Sha512
            } else {
                HashAlgorithm::Sha256
            };
            // TODO: localize
            let title = if sha512 {
                "SHA-512 Calculated"
            } else {
                "SHA-256 Calculated"
            };
            spawn_local(async move {
                let result =
                    spawn_worker(async move { hash_file(&selected, algorithm, &job) }).await;
                let Some(ui) = weak.upgrade() else { return };
                if !finish_job(&ui, &state, serial) {
                    return;
                }
                match result {
                    Ok((hash, bytes)) => {
                        // TODO: localize
                        set_result(
                            &ui,
                            3,
                            title,
                            "This identifies the file's bytes, not its publisher.",
                            &format!(
                                "{name}\n{bytes} bytes\n\n{}",
                                grouped_hex(&encode_hex(&hash), 16)
                            ),
                            "",
                            false,
                        );
                        ui.global::<VerifyState>().set_can_compare(true);
                    }
                    Err(error) => show_job_error(&ui, &error),
                }
            })
            .detach();
            true
        }
    });

    macro_rules! picker {
        ($callback:ident, $field:ident, $setter:ident) => {
            actions.$callback({
                let weak = ui.as_weak();
                let state = state.clone();
                move || {
                    let Some(ui) = weak.upgrade() else { return };
                    clear_error(&ui);
                    match pick_file() {
                        Ok(Some(file)) => {
                            ui.global::<VerifyState>()
                                .$setter(display_name(file.name()).into());
                            state.borrow_mut().$field = Some(file);
                        }
                        Ok(None) => {}
                        Err(error) => {
                            fail(&ui, &error);
                        }
                    }
                }
            });
        };
    }
    actions.on_select_compare_checksums({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            clear_error(&ui);
            match pick_file() {
                Ok(Some(file)) => {
                    ui.global::<VerifyState>()
                        .set_compare_checksums(display_name(file.name()).into());
                    state.borrow_mut().compare_checksums = Some(ChecksumSource::File(file));
                }
                Ok(None) => {}
                Err(error) => {
                    fail(&ui, &error);
                }
            }
        }
    });
    actions.on_use_expected({
        let weak = ui.as_weak();
        let state = state.clone();
        move |text| {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            clear_error(&ui);
            match parse_expected_digest(&text) {
                Ok(digest) => {
                    // TODO: localize
                    let label = if digest.len() == 32 {
                        "Entered SHA-256 hash"
                    } else {
                        "Entered SHA-512 hash"
                    };
                    ui.global::<VerifyState>()
                        .set_compare_checksums(label.into());
                    state.borrow_mut().compare_checksums = Some(ChecksumSource::Digest(digest));
                    true
                }
                Err(error) => fail(&ui, &error),
            }
        }
    });
    picker!(
        on_select_release_artifact,
        release_artifact,
        set_release_artifact
    );
    picker!(
        on_select_release_manifest,
        release_manifest,
        set_release_manifest
    );
    picker!(
        on_select_release_signature,
        release_signature,
        set_release_signature
    );
    actions.on_select_release_key_file({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            clear_error(&ui);
            match pick_file() {
                Ok(Some(file)) => {
                    ui.global::<VerifyState>()
                        .set_release_key(display_name(file.name()).into());
                    state.borrow_mut().release_key = Some(file);
                    true
                }
                Ok(None) => false,
                Err(error) => fail(&ui, &error),
            }
        }
    });
    actions.on_select_saved_release_key({
        let weak = ui.as_weak();
        let state = state.clone();
        move |fingerprint| {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            clear_error(&ui);
            let fingerprint = compact_fingerprint(&fingerprint);
            let label = {
                let current = state.borrow();
                if !current.trusted.contains(&fingerprint)
                    || !current.trusted.key_available(&fingerprint)
                {
                    // TODO: localize
                    return fail(&ui, "Re-import this publisher key before using it.");
                }
                let label = current
                    .trusted
                    .entries()
                    .find(|(stored, _)| stored.eq_ignore_ascii_case(&fingerprint))
                    .and_then(|(_, details)| details.as_ref())
                    .map(|details| {
                        if details.name.is_empty() {
                            details.email.as_str()
                        } else {
                            details.name.as_str()
                        }
                    })
                    .filter(|label| !label.is_empty())
                    // TODO: localize
                    .unwrap_or("Saved publisher key")
                    .to_owned();
                label
            };
            let Some(path) = trusted_key_path(&fingerprint) else {
                // TODO: localize
                return fail(&ui, "The saved publisher fingerprint is invalid.");
            };
            match load_trusted_key(&path) {
                Ok(()) => {
                    state.borrow_mut().release_key = Some(SelectedFile {
                        path,
                        location: fs::Location::AppData,
                    });
                    // TODO: localize
                    ui.global::<VerifyState>()
                        .set_release_key(format!("Saved: {label}").into());
                    true
                }
                Err(error) => fail(&ui, &error),
            }
        }
    });

    actions.on_compare_file({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return false };
            clear_error(&ui);
            let selected = {
                let current = state.borrow();
                current.compare_artifact.clone().zip(current.compare_checksums.clone())
            };
            let Some((artifact, checksums)) = selected else {
                // TODO: localize
                return fail(&ui, "Choose a file and add its expected checksum first.");
            };
            let name = display_name(artifact.name());
            let (serial, job) = begin_job(&ui, &state);
            let weak = ui.as_weak();
            let state = state.clone();
            spawn_local(async move {
                let result = spawn_worker(async move { compare(&artifact, &checksums, &job) }).await;
                let Some(ui) = weak.upgrade() else { return };
                if !finish_job(&ui, &state, serial) { return; }
                match result {
                    Ok((matches, hash, algorithm)) => {
                        if matches {
                            // TODO: localize
                            set_result(&ui, 0, "Checksum Matches", "The bytes match. Publisher identity has not been verified.",
                                &format!("{name}\n{algorithm}\n\n{}", grouped_hex(&hash, 16)), "", false);
                        } else {
                            // TODO: localize
                            set_result(&ui, 2, "Checksum Mismatch", "Do not use this download. Its bytes do not match the expected checksum.",
                                &format!("{name}\nCalculated {algorithm}\n\n{}", grouped_hex(&hash, 16)), "", false);
                        }
                    }
                    Err(error) => show_job_error(&ui, &error),
                }
            }).detach();
            true
        }
    });

    actions.on_verify_release({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return false };
            clear_error(&ui);
            let selected = {
                let current = state.borrow();
                current.release_artifact.clone().zip(current.release_manifest.clone())
                    .zip(current.release_signature.clone()).zip(current.release_key.clone())
            };
            let Some((((artifact, manifest), signature), key)) = selected else {
                // TODO: localize
                return fail(&ui, "Choose the release, manifest, signature, and publisher key first.");
            };
            let name = display_name(artifact.name());
            let (serial, job) = begin_job(&ui, &state);
            let weak = ui.as_weak();
            let state = state.clone();
            spawn_local(async move {
            let result = spawn_worker(async move {
                let manifest_bytes = read_bounded(&manifest, MAX_MANIFEST_BYTES)?;
                let signature_bytes = read_bounded(&signature, MAX_SIGNATURE_BYTES)?;
                let key_bytes = read_bounded(&key, MAX_PUBLIC_KEY_BYTES)?;
                let identity = verify_detached_signature(&manifest_bytes, &signature_bytes, &key_bytes)?;
                let text = std::str::from_utf8(&manifest_bytes)
                    // TODO: localize
                    .map_err(|_| "The checksum manifest is not UTF-8 text.".to_string())?;
                let entries = parse_manifest(text)?;
                let entry = find_manifest_entry(&entries, artifact.name())?;
                let (actual, _) = hash_file(&artifact, entry.algorithm, &job)?;
                if !digest_matches(&entry.digest, &actual) {
                    // TODO: localize
                    return Err("The signature is valid, but the release checksum does not match. Do not use this download.".to_string());
                }
                Ok((identity, key_bytes))
            }).await;
            let Some(ui) = weak.upgrade() else { return };
            if !finish_job(&ui, &state, serial) { return; }
            let mut current = state.borrow_mut();

            match result {
                Ok((identity, key_bytes)) => {
                    let trusted = current.trusted.contains(&identity.fingerprint);
                    let fingerprint = grouped_fingerprint(&identity.fingerprint);
                    let publisher = identity.user_id.as_deref().map(display_name)
                        // TODO: localize
                        .unwrap_or_else(|| "No publisher name in key".into());
                    if trusted {
                        let mut updated = current.trusted.clone();
                        let mut details_error = save_trusted_key(&identity.fingerprint, &key_bytes).err();
                        let mut changed = updated.refresh_details(&identity);
                        if details_error.is_none() {
                            changed |= updated.remember_key(&identity.fingerprint);
                        }
                        if changed {
                            match save_trusted_keys(&updated) {
                                Ok(()) => {
                                    current.trusted = updated;
                                    push_trusted_keys(&ui, &current.trusted);
                                }
                                Err(error) => details_error = Some(error),
                            }
                        }
                        // TODO: localize
                        set_result(&ui, 0, "Release Verified", "The signature and checksum match a publisher key you have trusted.",
                            &format!("{name}\n\n{publisher}"), &fingerprint, false);
                        if let Some(error) = details_error {
                            // TODO: localize
                            ui.global::<VerifyState>().set_result_detail(
                                format!("{name}\n\n{publisher}\n\nPublisher key could not be saved for reuse: {}", short_error(&error)).into());
                        }
                    } else {
                        // TODO: localize
                        set_result(&ui, 1, "Signature and Hash Match", "Check this fingerprint using a separate trusted source before trusting the publisher.",
                            &format!("{name}\n\n{publisher}"), &fingerprint, true);
                        current.pending_trust = Some(PendingTrust { identity, key_bytes });
                    }
                }
                Err(error) => {
                    show_job_error(&ui, &error);
                }
            }
            }).detach();
            true
        }
    });

    actions.on_trust_current_key({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let mut current = state.borrow_mut();
            let Some(pending) = current.pending_trust.clone() else {
                return;
            };
            let mut trusted = current.trusted.clone();
            if let Err(error) = trusted.remember(&pending.identity) {
                show_job_error(&ui, &error);
                return;
            }
            if let Err(error) = save_trusted_key(&pending.identity.fingerprint, &pending.key_bytes) {
                // TODO: localize
                set_result(&ui, 1, "Key Not Saved", "The signature and checksum match, but the public key could not be saved for reuse.", &short_error(&error), "", false);
                return;
            }
            trusted.remember_key(&pending.identity.fingerprint);
            if let Err(error) = save_trusted_keys(&trusted) {
                remove_trusted_key_file(&pending.identity.fingerprint);
                // TODO: localize
                set_result(
                    &ui,
                    1,
                    "Key Not Saved",
                    "The signature and checksum match, but the key could not be saved as trusted.",
                    &short_error(&error.to_string()),
                    "",
                    false,
                );
                return;
            }
            current.trusted = trusted;
            push_trusted_keys(&ui, &current.trusted);
            current.pending_trust = None;
            let view = ui.global::<VerifyState>();
            view.set_result_kind(0);
            // TODO: localize
            view.set_result_title("Release Verified".into());
            // TODO: localize
            view.set_result_summary(
                "The signature and checksum match. You have trusted this publisher key.".into(),
            );
            view.set_can_trust(false);
            view.set_can_compare(false);
        }
    });

    actions.on_forget_trusted_key({
        let weak = ui.as_weak();
        let state = state.clone();
        move |fingerprint| {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            clear_error(&ui);
            let fingerprint = fingerprint.split_whitespace().collect::<String>();
            let mut current = state.borrow_mut();
            let mut updated = current.trusted.clone();
            if !updated.forget(&fingerprint) {
                // TODO: localize
                return fail(&ui, "This publisher key is no longer saved.");
            }
            if let Err(error) = save_trusted_keys(&updated) {
                return fail(&ui, &error);
            }
            current.trusted = updated;
            if current.pending_trust.as_ref().is_some_and(|pending| {
                pending
                    .identity
                    .fingerprint
                    .eq_ignore_ascii_case(&fingerprint)
            }) {
                current.pending_trust = None;
            }
            push_trusted_keys(&ui, &current.trusted);
            remove_trusted_key_file(&fingerprint);
            true
        }
    });

    actions.on_forget_trusted_keys({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            clear_error(&ui);
            let fingerprints = state
                .borrow()
                .trusted
                .entries()
                .map(|(fingerprint, _)| fingerprint.clone())
                .collect::<Vec<_>>();
            if let Err(error) =
                FileSystem::default().durable_file_write(TRUST_FILE, fs::Location::AppData, b"")
            {
                fail(&ui, &error.to_string());
                return;
            }
            let mut current = state.borrow_mut();
            current.trusted.clear();
            push_trusted_keys(&ui, &current.trusted);
            drop(current);
            for fingerprint in fingerprints {
                remove_trusted_key_file(&fingerprint);
            }
        }
    });

    actions.on_reset({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let mut current = state.borrow_mut();
            if let Some(job) = current.job.take() {
                job.cancelled.store(true, Ordering::Relaxed);
            }
            let trusted = current.trusted.clone();
            let job_serial = current.job_serial + 1;
            *current = State {
                trusted,
                job_serial,
                ..State::default()
            };
            clear_error(&ui);
            let view = ui.global::<VerifyState>();
            view.set_busy(false);
            view.set_expected_draft("".into());
            // TODO: localize
            view.set_compare_artifact("No file selected".into());
            // TODO: localize
            view.set_compare_checksums("No checksum file selected".into());
            // TODO: localize
            view.set_release_artifact("No release selected".into());
            // TODO: localize
            view.set_release_manifest("No manifest selected".into());
            // TODO: localize
            view.set_release_signature("No signature selected".into());
            // TODO: localize
            view.set_release_key("No public key selected".into());
            view.set_can_trust(false);
            view.set_can_compare(false);
        }
    });
}

fn pick_file() -> Result<Option<SelectedFile>, String> {
    let options = SelectFileOptions::default()
        .with_allowed_locations(AllowedLocations::All)
        .with_allowed_extensions(AllowedExtensions::All)
        .with_hidden_allowed(false)
        .with_dirs_allowed(true)
        .with_multiple_selection_mode(false);
    let result = select_file::<GuiPermissions>(options)
        // TODO: localize
        .map_err(|error| format!("Could not open the file picker: {error}"))?;
    Ok(result
        .and_then(|result| result.files().first().cloned())
        .map(|(path, location)| SelectedFile {
            path,
            location: match location {
                Location::Internal => fs::Location::User,
                Location::Airlock => fs::Location::Airlock,
                Location::External => fs::Location::Usb,
            },
        }))
}

fn read_bounded(selected: &SelectedFile, limit: usize) -> Result<Vec<u8>, String> {
    let file = FileSystem::default()
        .open_file(&selected.path, selected.location, fs::OpenFlags::READ_ONLY)
        // TODO: localize
        .map_err(|error| format!("Could not open {}: {error}", selected.name()))?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        // TODO: localize
        .map_err(|error| format!("Could not read {}: {error}", selected.name()))?;
    if bytes.len() > limit {
        // TODO: localize
        return Err(format!(
            "{} exceeds the {} KiB safety limit.",
            selected.name(),
            limit / 1024
        ));
    }
    Ok(bytes)
}

fn hash_file(
    selected: &SelectedFile,
    algorithm: HashAlgorithm,
    job: &Job,
) -> Result<(Vec<u8>, u64), String> {
    let mut file = FileSystem::default()
        .open_file(&selected.path, selected.location, fs::OpenFlags::READ_ONLY)
        // TODO: localize
        .map_err(|error| format!("Could not open {}: {error}", selected.name()))?;
    let algorithm = match algorithm {
        HashAlgorithm::Sha256 => crypto::ShaAlgo::Sha256,
        HashAlgorithm::Sha512 => crypto::ShaAlgo::Sha512,
    };
    let mut hash = CryptoApi::default().sha_init(algorithm);
    let total = verify_core::stream_bytes(
        &mut file,
        || job.cancelled.load(Ordering::Relaxed),
        |chunk| hash.update(chunk).map_err(|error| error.to_string()),
        |total| {
            job.kib_processed.store(
                (total / 1024).min(u64::from(u32::MAX)) as u32,
                Ordering::Relaxed,
            )
        },
    )?;
    Ok((hash.finalize().map_err(|error| error.to_string())?, total))
}

fn compare(
    artifact: &SelectedFile,
    checksums: &ChecksumSource,
    job: &Job,
) -> Result<(bool, String, &'static str), String> {
    let entry = match checksums {
        ChecksumSource::File(file) => {
            let bytes = read_bounded(file, MAX_MANIFEST_BYTES)?;
            // TODO: localize
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| "The checksum file is not UTF-8 text.".to_string())?;
            let entries = parse_manifest(text)?;
            find_manifest_entry(&entries, artifact.name())?.clone()
        }
        ChecksumSource::Digest(digest) => verify_core::ManifestEntry {
            algorithm: if digest.len() == 32 {
                HashAlgorithm::Sha256
            } else {
                HashAlgorithm::Sha512
            },
            digest: digest.clone(),
            filename: None,
        },
    };
    let (actual, _) = hash_file(artifact, entry.algorithm, job)?;
    let algorithm = match entry.algorithm {
        HashAlgorithm::Sha256 => "SHA-256",
        HashAlgorithm::Sha512 => "SHA-512",
    };
    Ok((
        digest_matches(&entry.digest, &actual),
        encode_hex(&actual),
        algorithm,
    ))
}

fn load_trusted_keys() -> TrustStore {
    let Ok(bytes) = FileSystem::default().durable_file_read(TRUST_FILE, fs::Location::AppData)
    else {
        return TrustStore::default();
    };
    TrustStore::from_bytes(&bytes)
}

fn save_trusted_keys(trusted: &TrustStore) -> Result<(), String> {
    let bytes = trusted.to_bytes()?;
    FileSystem::default()
        .durable_file_write(TRUST_FILE, fs::Location::AppData, &bytes)
        .map_err(|error| error.to_string())
}

fn compact_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .split_whitespace()
        .collect::<String>()
        .to_ascii_uppercase()
}

fn trusted_key_path(fingerprint: &str) -> Option<String> {
    let fingerprint = compact_fingerprint(fingerprint);
    if !matches!(fingerprint.len(), 40 | 64)
        || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(format!("{TRUSTED_KEY_PREFIX}{fingerprint}.pgp"))
}

fn save_trusted_key(fingerprint: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC_KEY_BYTES {
        // TODO: localize
        return Err("The verified public key has an invalid size.".into());
    }
    let path = trusted_key_path(fingerprint)
        // TODO: localize
        .ok_or_else(|| "The verified publisher fingerprint is invalid.".to_string())?;
    FileSystem::default()
        .durable_file_write(&path, fs::Location::AppData, bytes)
        .map_err(|error| error.to_string())
}

fn load_trusted_key(path: &str) -> Result<(), String> {
    let bytes = FileSystem::default()
        .durable_file_read(path, fs::Location::AppData)
        // TODO: localize
        .map_err(|error| format!("The saved public key is unavailable: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC_KEY_BYTES {
        // TODO: localize
        return Err("The saved public key is invalid. Re-import it and try again.".into());
    }
    Ok(())
}

fn remove_trusted_key_file(fingerprint: &str) {
    let Some(path) = trusted_key_path(fingerprint) else {
        return;
    };
    let fs = FileSystem::default();
    let _ = fs.remove(&path, fs::Location::AppData);
    let _ = fs.remove(format!("{path}.tmp"), fs::Location::AppData);
    let _ = fs.remove(format!("{path}.new"), fs::Location::AppData);
}

fn push_trusted_keys(ui: &AppWindow, trusted: &TrustStore) {
    let keys = trusted
        .entries()
        .map(|(fingerprint, details)| SavedPublisher {
            fingerprint: grouped_fingerprint(fingerprint).into(),
            name: details
                .as_ref()
                .map(|d| d.name.as_str())
                .unwrap_or("")
                .into(),
            email: details
                .as_ref()
                .map(|d| d.email.as_str())
                .unwrap_or("")
                .into(),
            details_available: details.is_some(),
            key_available: trusted.key_available(fingerprint),
        })
        .collect::<Vec<_>>();
    let view = ui.global::<VerifyState>();
    view.set_trusted_keys(ModelRc::new(VecModel::from(keys)));
}

fn grouped_hex(hex: &str, width: usize) -> String {
    hex.as_bytes()
        .chunks(width)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn grouped_fingerprint(hex: &str) -> String {
    hex.as_bytes()
        .chunks(20)
        .map(|line| {
            line.chunks(4)
                .map(|group| std::str::from_utf8(group).unwrap_or(""))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn begin_job(ui: &AppWindow, state: &Rc<RefCell<State>>) -> (u64, Job) {
    let job = Job::default();
    let serial = {
        let mut current = state.borrow_mut();
        if let Some(job) = current.job.take() {
            job.cancelled.store(true, Ordering::Relaxed);
        }
        current.job_serial += 1;
        current.pending_trust = None;
        current.job = Some(job.clone());
        current.job_serial
    };
    // TODO: localize
    set_result(
        ui,
        3,
        "Checking File",
        "Keep the drive connected. You can cancel at any time.",
        "Starting...",
        "",
        false,
    );
    ui.global::<VerifyState>().set_busy(true);
    let weak = ui.as_weak();
    let state = state.clone();
    let progress = job.clone();
    spawn_local(async move {
        loop {
            sleep(Duration::from_millis(250)).await;
            if state.borrow().job_serial != serial || state.borrow().job.is_none() {
                break;
            }
            let Some(ui) = weak.upgrade() else { break };
            let kib = progress.kib_processed.load(Ordering::Relaxed);
            // TODO: localize
            ui.global::<VerifyState>()
                .set_result_detail(format!("{} KiB processed", kib).into());
        }
    })
    .detach();
    (serial, job)
}

fn finish_job(ui: &AppWindow, state: &Rc<RefCell<State>>, serial: u64) -> bool {
    let mut current = state.borrow_mut();
    if current.job_serial != serial {
        return false;
    }
    current.job = None;
    ui.global::<VerifyState>().set_busy(false);
    true
}

fn show_job_error(ui: &AppWindow, error: &str) {
    // TODO: localize
    set_result(
        ui,
        2,
        "Verification Failed",
        "Do not use this download until the problem is resolved.",
        &short_error(error),
        "",
        false,
    );
}

fn display_name(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_control() && !matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .take(80)
        .collect()
}

fn short_error(error: &str) -> String {
    error
        .chars()
        .filter(|character| !character.is_control())
        .take(220)
        .collect()
}

fn clear_error(ui: &AppWindow) {
    ui.global::<VerifyState>().set_error("".into());
}

fn fail(ui: &AppWindow, error: &str) -> bool {
    ui.global::<VerifyState>()
        .set_error(short_error(error).into());
    false
}

#[allow(clippy::too_many_arguments)]
fn set_result(
    ui: &AppWindow,
    kind: i32,
    title: &str,
    summary: &str,
    detail: &str,
    fingerprint: &str,
    can_trust: bool,
) {
    let view = ui.global::<VerifyState>();
    view.set_result_kind(kind);
    view.set_result_title(title.into());
    view.set_result_summary(summary.into());
    view.set_result_detail(detail.into());
    view.set_result_fingerprint(fingerprint.into());
    view.set_can_trust(can_trust);
    view.set_can_compare(false);
}

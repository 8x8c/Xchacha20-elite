use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Arg, Command};
use rpassword::prompt_password;
use zeroize::Zeroize;

// Argon2 for password-based key derivation
use argon2::{Argon2, Algorithm, Version, Params};

// Rand for generating salt/nonce
use rand::{rng, RngCore};

// XChaCha20-Poly1305 AEAD
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;

/// 8-byte magic header to detect whether file is encrypted or plaintext.
/// If file starts with these bytes, we assume it's XChaCha20-Poly1305–encrypted by this tool.
const MAGIC_HEADER: &[u8] = b"MYXCHAPP";
const MAGIC_HEADER_LEN: usize = 8;

/// Argon2 parameters for password → key derivation:
const ARGON2_MEMORY_KIB: u32 = 65536;  // 64 MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const DERIVED_KEY_LEN: usize = 32;     // 32 bytes => XChaCha20-Poly1305 key
const SALT_LEN: usize = 16;           // 16-byte salt
const XCHACHA_NONCE_LEN: usize = 24;  // 24-byte XNonce for XChaCha20-Poly1305

fn main() -> Result<()> {
    // A simple CLI that requires exactly one argument: <file>.
    // We'll disable the built-in help/version flags for brevity,
    // but you can remove .disable_* if you want them.
    let cmd = Command::new("mysecureapp-xchacha")
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("file")
                .required(true)
                .help("File to encrypt or decrypt in-place with XChaCha20-Poly1305."),
        );

    // Parse, but handle errors ourselves to avoid default usage messages
    let matches = match cmd.try_get_matches() {
        Ok(m) => m,
        Err(_) => {
            eprintln!("Error: No file argument provided.");
            std::process::exit(1);
        }
    };

    let file_path = matches
        .get_one::<String>("file")
        .expect("A file path is required (but wasn't provided).");

    in_place_mode(file_path)
}

/// Reads the file, detects if it's encrypted by checking magic header,
/// and either encrypts or decrypts in place.
fn in_place_mode(path_str: &str) -> Result<()> {
    let path = Path::new(path_str);

    // Read the entire file into memory
    let data = fs::read(path)
        .with_context(|| format!("Failed to read file '{}'", path.display()))?;

    // Detect mode
    let mode = detect_mode(&data);
    match mode {
        FileMode::Encrypt => {
            // For encryption, prompt password twice
            let mut pw1 = prompt_password("Enter password to encrypt: ")?;
            if pw1.is_empty() {
                return Err(anyhow!("Password cannot be empty."));
            }
            let mut pw2 = prompt_password("Confirm password: ")?;
            if pw1 != pw2 {
                pw1.zeroize();
                pw2.zeroize();
                return Err(anyhow!("Passwords do not match. Aborting."));
            }
            pw2.zeroize(); // done with the second password

            // Encrypt
            let ciphertext = encrypt_data(&data, &mut pw1)?;

            // Overwrite the file in place (atomic rename)
            atomic_overwrite(path, &ciphertext)?;
            println!("File encrypted in-place: '{}'", path.display());

            // Zeroize
            pw1.zeroize();
        }
        FileMode::Decrypt => {
            // For decryption, prompt once
            let mut pw = prompt_password("Enter password to decrypt: ")?;
            if pw.is_empty() {
                return Err(anyhow!("Password cannot be empty."));
            }

            // Decrypt
            let plaintext = decrypt_data(&data, &mut pw)?;
            atomic_overwrite(path, &plaintext)?;
            println!("File decrypted in-place: '{}'", path.display());

            pw.zeroize();
        }
    }

    Ok(())
}

/// Checks the first bytes for the magic header => if present, decrypt; otherwise, encrypt.
fn detect_mode(file_data: &[u8]) -> FileMode {
    if file_data.len() >= MAGIC_HEADER_LEN && &file_data[..MAGIC_HEADER_LEN] == MAGIC_HEADER {
        FileMode::Decrypt
    } else {
        FileMode::Encrypt
    }
}

enum FileMode {
    Encrypt,
    Decrypt,
}

/// Encrypt the plaintext in memory:
/// Output = [magic header | salt(16) | XNonce(24) | ciphertext].
fn encrypt_data(plaintext: &[u8], password: &mut String) -> Result<Vec<u8>> {
    // 1) Generate random salt (16 bytes) for Argon2
    let mut salt = vec![0u8; SALT_LEN];
    rng().fill_bytes(&mut salt);

    // 2) Derive a 32-byte key from password + salt
    let mut key = derive_key_argon2id(password, &salt)?;

    // 3) Generate a random 24-byte XChaCha nonce
    let mut nonce_bytes = vec![0u8; XCHACHA_NONCE_LEN];
    rng().fill_bytes(&mut nonce_bytes);
    let xnonce = XNonce::from_slice(&nonce_bytes);

    // 4) Encrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create XChaCha20-Poly1305 instance: {:?}", e))?;

    let ciphertext = cipher
        .encrypt(xnonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

    // Construct the final output
    // [ MAGIC_HEADER | salt(16) | nonce(24) | ciphertext(...) ]
    let mut out = Vec::with_capacity(
        MAGIC_HEADER_LEN + SALT_LEN + XCHACHA_NONCE_LEN + ciphertext.len()
    );
    out.extend_from_slice(MAGIC_HEADER);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    // Zeroize sensitive data
    key.zeroize();
    salt.zeroize();
    nonce_bytes.zeroize();

    Ok(out)
}

/// Decrypt data from [magic header | salt(16) | nonce(24) | ciphertext].
fn decrypt_data(file_data: &[u8], password: &mut String) -> Result<Vec<u8>> {
    if file_data.len() < MAGIC_HEADER_LEN + SALT_LEN + XCHACHA_NONCE_LEN {
        return Err(anyhow!("File too short to contain header/salt/nonce."));
    }

    let salt_start = MAGIC_HEADER_LEN;
    let salt_end = salt_start + SALT_LEN;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + XCHACHA_NONCE_LEN;

    let salt_slice = &file_data[salt_start..salt_end];
    let nonce_slice = &file_data[nonce_start..nonce_end];
    let ciphertext = &file_data[nonce_end..];

    // 1) Derive key again
    let mut key = derive_key_argon2id(password, salt_slice)?;

    // 2) Decrypt using XChaCha
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create XChaCha20-Poly1305 instance: {:?}", e))?;

    let xnonce = XNonce::from_slice(nonce_slice);

    let plaintext = cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed: incorrect password or data corrupted."))?;

    // Zeroize
    key.zeroize();

    Ok(plaintext)
}

/// Argon2id password → 32-byte key derivation.
fn derive_key_argon2id(password: &mut String, salt: &[u8]) -> Result<Vec<u8>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|e| anyhow!("Argon2 parameter error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; DERIVED_KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 hash error: {}", e))?;

    Ok(key)
}

/// Atomically overwrite the original file with the new data (temp file → rename).
fn atomic_overwrite(path: &Path, data: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Invalid path: no file name."))?;

    let mut tmp_path = PathBuf::from(path);
    tmp_path.set_file_name(format!("{}.tmp", file_name.to_string_lossy()));

    fs::write(&tmp_path, data)
        .with_context(|| format!("Failed to write temporary file '{}'", tmp_path.display()))?;

    fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename '{}' -> '{}'", tmp_path.display(), path.display()))?;

    Ok(())
}


use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm,
};
use anyhow::Error;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

fn make_key_from_password(salt: &str, password: &str) -> [u8; 32] {
    let password = password.as_bytes();
    let salt = salt.as_bytes();
    // number of iterations
    const ITERATIONS: u32 = 600_000;

    pbkdf2_hmac_array::<Sha256, 32>(password, salt, ITERATIONS)
}

fn main() -> Result<(), Error> {
    let key = make_key_from_password("rms", "password");
    let cipher = Aes256Gcm::new((&key).into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let mut buffer = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
    buffer.extend_from_slice("plaintext message".as_bytes());

    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;

    // `buffer` now contains the message ciphertext
    assert_ne!(&buffer, b"plaintext message");

    // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
    cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
    assert_eq!(&buffer, b"plaintext message");
    Ok(())
}

use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm,
};
use anyhow::Error;
use hex_literal::hex;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

#[allow(unused)]
fn make_key_from_password(salt: &str, password: &str) -> [u8; 32] {
    let password = password.as_bytes();
    let salt = salt.as_bytes();
    // number of iterations
    const ITERATIONS: u32 = 600_000;

    pbkdf2_hmac_array::<Sha256, 32>(password, salt, ITERATIONS)
}

fn main() -> Result<(), Error> {
    // 32 byte random secret key for testing
    let key = hex!("9a39 72b9 c37a 64f7 0919 dcc4 dbe7 bd61 5bc7 9815 33ed 6928 abd5 7aff 9339 d271");

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

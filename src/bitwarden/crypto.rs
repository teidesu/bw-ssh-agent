use aes::cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut as _};
use base64::{prelude::BASE64_STANDARD, Engine};
use hkdf::Hkdf;
use hmac::Mac;
use pbkdf2::hmac::Hmac;
use sha2::Sha256;

pub fn make_master_key(password: &str, salt: &str, iterations: u32) -> color_eyre::Result<Vec<u8>> {
    let mut master_key = vec![0u8; 32];

    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut master_key,
    )?;

    Ok(master_key)
}

pub fn make_master_key_hash(master_key: &[u8], salt: &str) -> color_eyre::Result<String> {
    let mut master_key_hash = vec![0u8; 32];

    pbkdf2::pbkdf2::<Hmac<Sha256>>(master_key, salt.as_bytes(), 1, &mut master_key_hash)?;

    Ok(BASE64_STANDARD.encode(master_key_hash))
}

pub fn hkdf_expand_key(master_key: &[u8]) -> color_eyre::Result<[u8; 64]> {
    let mut expanded_key = [0u8; 64];

    let hk = Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|_| color_eyre::eyre::eyre!("Invalid master key"))?;

    hk.expand(b"enc", &mut expanded_key[..32])
        .map_err(|_| color_eyre::eyre::eyre!("Failed to expand enc key"))?;
    hk.expand(b"mac", &mut expanded_key[32..])
        .map_err(|_| color_eyre::eyre::eyre!("Failed to expand mac key"))?;

    Ok(expanded_key)
}

pub fn bw_decrypt_encstr(key: &[u8], encrypted_data: &str) -> color_eyre::Result<Vec<u8>> {
    let (enc_key, mac_key) = (&key[..32], &key[32..]);

    let header_pieces = encrypted_data.split(".").collect::<Vec<&str>>();

    let (enc_type, enc_pieces) = if header_pieces.len() == 1 {
        (3, vec![header_pieces[0]])
    } else {
        (
            header_pieces[0].parse::<u32>()?,
            header_pieces[1].split("|").collect::<Vec<&str>>(),
        )
    };

    // we only support AesCbc256_HmacSha256_B64 for now
    if enc_type != 2 {
        return Err(color_eyre::eyre::eyre!(
            "Unsupported encryption type {}",
            enc_type
        ));
    }

    if enc_pieces.len() != 3 {
        return Err(color_eyre::eyre::eyre!("Invalid encrypted data format"));
    }

    let iv = BASE64_STANDARD.decode(enc_pieces[0])?;
    let mut data = BASE64_STANDARD.decode(enc_pieces[1])?;
    let mac = BASE64_STANDARD.decode(enc_pieces[2])?;

    // verify the MAC
    let mut mac_expected = Hmac::<Sha256>::new_from_slice(mac_key)?;
    mac_expected.update(iv.as_slice());
    mac_expected.update(data.as_slice());
    mac_expected.verify_slice(mac.as_slice())?;

    // decrypt the content
    let key_enc = GenericArray::from_slice(enc_key);
    let iv = GenericArray::from_slice(iv.as_slice());
    let cipher = <cbc::Decryptor<aes::Aes256> as aes::cipher::KeyIvInit>::new(key_enc, iv);
    let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut data);

    match plaintext {
        Ok(plaintext) => Ok(plaintext.to_vec()),
        Err(e) => Err(color_eyre::eyre::eyre!(e)),
    }
}

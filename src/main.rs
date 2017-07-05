#![deny(missing_debug_implementations, missing_copy_implementations,
trivial_casts, trivial_numeric_casts, unsafe_code, unstable_features,
unused_import_braces, unused_qualifications)]

#![cfg_attr(feature="clippy", allow(unstable_features))]
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(non_ascii_literal))]

extern crate crypto;
extern crate encoji;

use crypto::{symmetriccipher, aes, blockmodes};
use crypto::buffer::{self, ReadBuffer, WriteBuffer, BufferResult};
use crypto::md5::Md5;
use crypto::digest::Digest;
use std::env;

fn main() {
    let args: Vec<_> = env::args().collect();
    let mode_defined = args.len() >= 4;

    let first_index = if mode_defined { 2 } else { 1 };

    let message = args[first_index].clone();
    let key = hash_key(&args[first_index + 1]);

    if mode_defined && args[1] == "decrypt" {
        let decrypted_data = decrypt(&encoji::from_string(&message), &key).ok().unwrap();
        println!("{}", String::from_utf8_lossy(&decrypted_data[..]));
    } else {
        let encrypted_data = encrypt(message.as_bytes(), &key).ok().unwrap();
        println!("{}", encoji::to_string(&encrypted_data[..]));
    }
}


fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        &[0; 16],
        blockmodes::PkcsPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .cloned(),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn decrypt(
    encrypted_data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        &[0; 16],
        blockmodes::PkcsPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .cloned(),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn hash_key(raw_key: &str) -> [u8; 32] {
    let mut hasher = Md5::new();

    hasher.input(raw_key.as_bytes());
    let mut output = [0; 32];
    hasher.result(&mut output);
    output
}

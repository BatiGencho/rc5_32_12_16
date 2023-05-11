//! This module implements the RC5-32/12/16 block cipher.

use displaydoc::Display as DisplayDoc;
use std::{convert::TryInto, ops::BitXor};
use thiserror::Error;

/// Errors exported by the encryption algorithm
#[non_exhaustive]
#[derive(Debug, DisplayDoc, Error)]
pub enum Error {
    /// invalid secret key length: `{0}`
    InvalidKeyLen(String),
    /// invalid encryption key length: `{0}`
    InvalidEncryptionDataLen(String),
    /// invalid decryption key length: `{0}`
    InvalidDecryptionDataLen(String),
}

/// Trait for RC5 encryption and decryption
pub trait Rc5Encryptor {
    /// Encrypts data in place using the RC5 algorithm
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be encrypted
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;
    /// Decrypts data in place using the RC5 algorithm
    ///
    /// # Arguments
    ///
    /// * `cypher` - The encrypted data to be decrypted
    fn decrypt(&mut self, cypher: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Trait defining constants for the RC5-32/12/16 algorithm
pub trait Rc5_32_12_16Defs {
    /// Version of the RC5-32/12/16 algorithm
    const VERSION: u32 = 1;
    /// Word size of the RC5-32/12/16 algorithm in bits
    const W: u32 = 32;
    /// Number of bytes per word of the RC5-32/12/16 algorithm
    const W_BYTES: usize = 8;
    /// Number of rounds in the RC5-32/12/16 algorithm
    const R: u32 = 12;
    /// Block size of the RC5-32/12/16 algorithm in bytes
    const B: u32 = 16;
    /// First magic constant used in the RC5-32/12/16 algorithm
    const P: u32 = 0xb7e15163u32;
    /// Second magic constant used in the RC5-32/12/16 algorithm
    const Q: u32 = 0x9E3779B9u32;
    /// Size of the expanded key table for the RC5-32/12/16 algorithm in words
    const T: u32 = 2 * (Self::R + 1);
    /// Number of words in the secret key for the RC5-32/12/16 algorithm
    const C: u32 = ((8 * Self::B) / Self::W);
    /// Number of bits to rotate in the setup phase of the RC5-32/12/16 algorithm
    const SETUP_BITS_ROT: u32 = 3;
}

/// RC5-32/12/16 encryption implementation
#[derive(Debug)]
pub struct Rc5_32_12_16Encryption {
    key_table: Vec<u32>, // key table (key Schedule)
    is_padded: bool,     // bool to mark if the padding was applied
    pad_len: usize,      // marks the padding length
}

impl Rc5_32_12_16Defs for Rc5_32_12_16Encryption {}

impl Rc5_32_12_16Encryption {
    /// Constructs a new instance of RC5-32/12/16 encryption with the given secret key.
    ///
    /// # Arguments
    ///
    /// * `key` - A slice of bytes representing the secret key used for encryption. The length of the key
    ///           must be within the range [0, 255] bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing a new instance of RC5-32/12/16 encryption, or an `Error` if there was a problem
    /// constructing the encryption instance.
    ///
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            key_table: Self::build_key_schedule(key)?,
            is_padded: false,
            pad_len: 0,
        })
    }

    /// Updates the secret key used for encryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The new secret key to be set.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided key length is not within the range of 1 to 255 bytes.
    ///
    pub fn update_secret_key(&mut self, key: &[u8]) -> Result<(), Error> {
        self.key_table = Self::build_key_schedule(key)?;
        Ok(())
    }

    /// Builds the key schedule for the RC5-32/12/16 algorithm
    ///
    /// # Arguments
    ///
    /// * `key` - The key to be used for generating a key schedule
    ///
    /// # Returns
    ///
    /// The key schedule generated from the given `key`
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue building the key schedule
    ///
    fn build_key_schedule(key: &[u8]) -> Result<Vec<u32>, Error> {
        // check key length
        if key.len() as u32 != Self::B {
            return Err(Error::InvalidKeyLen(format!(
                "Invalid key length: expected {} bytes, but got {}",
                Self::B,
                key.len()
            )));
        }

        let mut key_words = vec![0u32; Self::C as usize];

        // step1: converting the secret key from bytes to words
        let u = Self::W / Self::W_BYTES as u32;
        for i in (0..Self::B).rev() {
            key_words[(i / u) as usize] = key_words[(i / u) as usize]
                .rotate_left(Self::W_BYTES as u32)
                + (key[i as usize] as u32);
        }

        // step2: use key to initialize the expanded key array S
        let mut key_table = vec![0u32; Self::T as usize];
        key_table[0] = Self::P;
        for i in 1..Self::T {
            key_table[i as usize] = key_table[(i - 1) as usize].wrapping_add(Self::Q);
        }

        // step3: mixing in the secret key
        let (mut i, mut j) = (0, 0);
        let (mut a, mut b) = (0, 0);

        for _ in 0..3 * Self::T.max(Self::C) {
            key_table[i] = key_table[i]
                .wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(Self::SETUP_BITS_ROT);
            a = key_table[i];

            key_words[j] = key_words[j]
                .wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(a.wrapping_add(b));
            b = key_words[j];

            i = (i + 1) % key_table.len();
            j = (j + 1) % key_words.len();
        }
        Ok(key_table)
    }

    /// Parses a byte slice `block` and returns a tuple of two 32-bit integers
    ///
    /// # Arguments
    ///
    /// * `block` - A slice of bytes containing two 32-bit integers to be extracted
    ///
    /// # Returns
    ///
    /// A tuple of two 32-bit integers obtained by parsing the given byte slice `block`
    ///
    fn get_2w_from_block(block: &[u8]) -> (u32, u32) {
        let a = u32::from_le_bytes(block[..Self::W_BYTES / 2].try_into().unwrap());
        let b = u32::from_le_bytes(block[Self::W_BYTES / 2..].try_into().unwrap());
        (a, b)
    }

    /// Writes the two 32-bit integers `a` and `b` into the given byte slice `block`.
    ///
    /// # Arguments
    ///
    /// * `a` - The first 32-bit integer to be written.
    /// * `b` - The second 32-bit integer to be written.
    /// * `block` - A mutable slice of bytes to hold the two 32-bit integers.
    ///
    fn build_block_from_2w(a: u32, b: u32, block: &mut [u8]) {
        let (left, right) = block.split_at_mut(Self::W_BYTES / 2);
        left.copy_from_slice(&a.to_le_bytes());
        right.copy_from_slice(&b.to_le_bytes());
    }
}

impl Rc5Encryptor for Rc5_32_12_16Encryption {
    /// Encrypts the given data using the RC5 encryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - A mutable slice of bytes to be encrypted. The length of the slice must be a multiple of 16.
    ///
    /// # Returns
    ///
    /// The encrypted data as a `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the length of the input data is not a multiple of 16.
    ///
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // check data length
        if data.is_empty() {
            return Err(Error::InvalidEncryptionDataLen(format!(
                "Invalid data length: got {}",
                data.len()
            )));
        }
        // Pad input data with zeros if necessary
        let word_size = Self::B / 2;
        let last_block_size = data.len() as u32 % word_size;
        let (mut data_to_encrypt, is_padded, pad_len) = if last_block_size > 0 {
            let pad_len = word_size - last_block_size;
            let mut padded_data = vec![0; data.len() + pad_len as usize];
            padded_data[..data.len()].copy_from_slice(data);
            (padded_data, true, pad_len)
        } else {
            (data.to_vec(), false, 0)
        };

        let (mut a, mut b) = Self::get_2w_from_block(&data_to_encrypt);

        a = a.wrapping_add(self.key_table[0]);
        b = b.wrapping_add(self.key_table[1]);

        for i in 1..=Self::R {
            a = (a ^ b)
                .rotate_left(b)
                .wrapping_add(self.key_table[2 * i as usize]);
            b = (b ^ a)
                .rotate_left(a)
                .wrapping_add(self.key_table[(2 * i + 1) as usize]);
        }

        Self::build_block_from_2w(a, b, &mut data_to_encrypt);
        self.is_padded = is_padded;
        self.pad_len = pad_len as usize;
        Ok(data_to_encrypt)
    }

    /// Decrypts the given data using the RC5 decryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `cypher` - A mutable slice of bytes to be decrypted. The slice length must be a multiple of 16.
    ///
    /// # Returns
    ///
    /// Returns a Result containing the decrypted data as a Vec<u8> if the decryption is successful, otherwise an Error.
    ///
    fn decrypt(&mut self, cypher: &[u8]) -> Result<Vec<u8>, Error> {
        // check cypher length
        if cypher.is_empty() {
            return Err(Error::InvalidDecryptionDataLen(format!(
                "Invalid key length: got {}",
                cypher.len()
            )));
        }
        let mut decrypted_data = cypher.to_vec();
        let (mut a, mut b) = Self::get_2w_from_block(&decrypted_data);

        for i in (1..=Self::R).rev() {
            b = b
                .wrapping_sub(self.key_table[(2 * i + 1) as usize])
                .rotate_right(a)
                .bitxor(a);
            a = a
                .wrapping_sub(self.key_table[2 * i as usize])
                .rotate_right(b)
                .bitxor(b);
        }

        b = b.wrapping_sub(self.key_table[1]);
        a = a.wrapping_sub(self.key_table[0]);

        Self::build_block_from_2w(a, b, &mut decrypted_data);

        if self.is_padded {
            decrypted_data.truncate(decrypted_data.len() - self.pad_len);
        }

        Ok(decrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_article_results() {
        let test_data: [(&str, &str, &str); 5] = [
            (
                "00000000000000000000000000000000",
                "0000000000000000",
                "21A5DBEE154B8F6D",
            ),
            (
                "915F4619BE41B2516355A50110A9CE91",
                "21A5DBEE154B8F6D",
                "F7C013AC5B2B8952",
            ),
            (
                "783348E75AEB0F2FD7B169BB8DC16787",
                "F7C013AC5B2B8952",
                "2F42B3B70369FC92",
            ),
            (
                "DC49DB1375A5584F6485B413B5F12BAF",
                "2F42B3B70369FC92",
                "65C178B284D197CC",
            ),
            (
                "5269F149D41BA0152497574D7F153125",
                "65C178B284D197CC",
                "EB44E415DA319824",
            ),
        ];
        for (test_key, test_plaintext, test_cypher) in test_data.iter() {
            let key_bytes = Vec::from_hex(test_key).unwrap();
            // init with key
            let mut rc5 = Rc5_32_12_16Encryption::new(&key_bytes).expect("Should be initialized");
            // plaintext to encrypt
            let plaintext_to_encrypt = Vec::from_hex(test_plaintext).unwrap();
            // encrypt
            let cypher = rc5
                .encrypt(&plaintext_to_encrypt)
                .expect("Should be encrypted");
            assert!(cypher.eq_ignore_ascii_case(&hex::decode(&test_cypher).unwrap()));
            // decrypt
            let decrypted_data = rc5.decrypt(&cypher).expect("Should be decrypted");
            assert!(decrypted_data.eq_ignore_ascii_case(&hex::decode(&test_plaintext).unwrap()));
        }
    }

    #[test]
    fn test_unpadded_edge_case() {
        let test_key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        // init with key
        let mut rc5 = Rc5_32_12_16Encryption::new(&test_key).expect("Should be initialized");
        // plaintext to encrypt
        let plaintext_to_encrypt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D]; // only 7 bytes long
        let cypher = rc5
            .encrypt(&plaintext_to_encrypt)
            .expect("Should be encrypted");
        // decrypt
        let decrypted_data = rc5.decrypt(&cypher).expect("Should be decrypted");
        assert!(plaintext_to_encrypt.eq(&decrypted_data));
    }

    #[test]
    fn test_unpadded_edge_case1() {
        let test_key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        // init with key
        let mut rc5 = Rc5_32_12_16Encryption::new(&test_key).expect("Should be initialized");
        // plaintext to encrypt
        let plaintext_to_encrypt = vec![0x96]; // only 1 bytes long
        let cypher = rc5
            .encrypt(&plaintext_to_encrypt)
            .expect("Should be encrypted");
        // decrypt
        let decrypted_data = rc5.decrypt(&cypher).expect("Should be decrypted");
        assert!(plaintext_to_encrypt.eq(&decrypted_data));
    }

    #[test]
    fn test_invalid_key_len() {
        let test_key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        ];
        assert!(Rc5_32_12_16Encryption::new(&test_key).is_err());
    }

    #[test]
    fn test_invalid_encryption_data_len() {
        let test_key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        // init with key
        let mut rc5 = Rc5_32_12_16Encryption::new(&test_key).expect("Should be initialized");
        // plaintext to encrypt
        let plaintext_to_encrypt = vec![]; // 0 bytes long
        assert!(rc5.encrypt(&plaintext_to_encrypt).is_err());
    }

    #[test]
    fn test_invalid_decryption_data_len() {
        let test_key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        // init with key
        let mut rc5 = Rc5_32_12_16Encryption::new(&test_key).expect("Should be initialized");
        // plaintext to encrypt
        let plaintext_to_encrypt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x08];
        let mut cypher = rc5
            .encrypt(&plaintext_to_encrypt)
            .expect("Should be encrypted");
        // decrypt
        cypher.clear();
        assert!(rc5.decrypt(&cypher).is_err());
    }
}

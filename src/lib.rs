mod rc5;
pub use rc5::{Error, Rc5Encryptor, Rc5_32_12_16Encryption};

#[cfg(test)]
mod tests {
    use crate::rc5::{Rc5Encryptor, Rc5_32_12_16Encryption};

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt: Vec<u8> = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]; // plaintext
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E]; // cypher

        let mut rc5 = Rc5_32_12_16Encryption::new(&key).expect("Should be initialized");
        let cypher = rc5.encrypt(&pt).expect("Should be decrypted");
        assert!(&ct[..] == &cypher[..]);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];

        let mut rc5 = Rc5_32_12_16Encryption::new(&key).expect("Should be initialized");
        // encrypt
        let cypher = rc5.encrypt(&pt).expect("Should be encrypted");
        assert!(&ct[..] == &cypher[..]);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let _ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let mut rc5 = Rc5_32_12_16Encryption::new(&key).expect("Should be initialized");
        let cypher = rc5.encrypt(&pt).expect("Should be encrypted");
        let decrypted_data = rc5.decrypt(&cypher).expect("Should be decrypted");
        assert!(&pt[..] == &decrypted_data[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let _ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let mut rc5 = Rc5_32_12_16Encryption::new(&key).expect("Should be initialized");
        let cypher = rc5.encrypt(&pt).expect("Should be encrypted");
        let decrypted_data = rc5.decrypt(&cypher).expect("Should be decrypted");
        assert!(&pt[..] == &decrypted_data[..]);
    }
}

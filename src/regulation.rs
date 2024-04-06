use std::io::Read;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::cipher::block_padding::NoPadding;
use thiserror::Error;
use crate::dcx::{DCXError, DcxReader};

pub struct Regulation {
    pub parambnd: Vec<u8>,
}

impl Regulation {
    pub fn from_encrypted_compressed(input: impl AsRef<[u8]>) -> Result<Regulation, RegulationError> {
        let input = input.as_ref();
        let (iv, enc_data) = input.split_first_chunk::<IV_LENGTH>().ok_or(RegulationError::MalformedInput)?;
        let dec = Decryptor::new((&ER_KEY).into(), iv.into());
        let v = dec.decrypt_padded_vec_mut::<NoPadding>(enc_data).map_err(|_| RegulationError::DecryptInputTooShort)?;
        Self::from_decrypted_compressed(&v)
    }

    fn from_decrypted_compressed(input: &[u8]) -> Result<Regulation, RegulationError> {
        let mut reader = DcxReader::new(input)?;
        let mut output = Vec::with_capacity(reader.size_hint() as usize);
        reader.read_to_end(&mut output).map_err(|_| RegulationError::DCXError(DCXError::Decompression))?;
        Ok(Regulation { parambnd: output })
    }
}

type Decryptor = cbc::Decryptor<aes::Aes256>;

const ER_KEY: [u8; 32] = hex_literal::hex!(
    "99 BF FC 36 6A 6B C8 C6 F5 82 7D 09 36 02 D6 76 C4 28 92 A0 1C 20 7F B0 24 D3 AF 4E 49 3F EF 99"
);

const IV_LENGTH: usize = 16;

#[derive(Error, Debug)]
pub enum RegulationError {
    #[error("The input was too short to decrypt")]
    DecryptInputTooShort,
    #[error("The input was malformed")]
    MalformedInput,
    #[error("An error occurred while decompressing: {0}")]
    DCXError(#[from] DCXError),
}

#[cfg(test)]
mod tests {
    use super::*;
    const DATA: &[u8] = include_bytes!("../data/regulation.bin");

    #[test]
    fn it_works() {
        Regulation::from_encrypted_compressed(DATA).unwrap();
    }
}

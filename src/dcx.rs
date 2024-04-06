use std::io::Read;
use std::mem::size_of;

use byteorder::BigEndian;
use flate2::read::ZlibDecoder;
use thiserror::Error;
use zerocopy::{AsBytes, FromBytes, U32, Ref, FromZeroes};

#[derive(FromZeroes, FromBytes, AsBytes, Debug)]
#[repr(C)]
struct Metadata {
    dcx_magic: [u8; 4],
    format_magic: [u8; 4],
    dcs_offset: U32<BigEndian>,
    dcp_offset: U32<BigEndian>,
    unk1: U32<BigEndian>,
    unk2: U32<BigEndian>,
    dcs_magic: [u8; 4],
    compressed_size: U32<BigEndian>,
    size: U32<BigEndian>,
    dcp_magic: [u8; 4],
    algorithm: [u8; 4],
    unk3: [u32; 6],
    dca_magic: [u8; 4],
    dca_size: U32<BigEndian>,
}

pub struct DcxReader<R: Read> {
    size_hint: u32,
    codec: DcxCompressionCodec<R>,
}

enum DcxCompressionCodec<R: Read> {
    Deflate(ZlibDecoder<R>),
}

impl<R: Read> DcxReader<R> {
    pub fn new(mut reader: R) -> Result<Self, DCXError> {
        let mut header_buffer = [0u8; size_of::<Metadata>()];
        reader.read_exact(&mut header_buffer)?;

        let header = Ref::<_, Metadata>::new(&header_buffer[..]).unwrap();

        if &header.dcx_magic != b"DCX\0" { return Err(DCXError::MalformedMetadata); }
        if &header.dcp_magic != b"DCP\0" { return Err(DCXError::MalformedMetadata); }
        if &header.dcs_magic != b"DCS\0" { return Err(DCXError::MalformedMetadata); }

        let codec = match &header.algorithm {
            b"DFLT" => Ok(DcxCompressionCodec::Deflate(ZlibDecoder::new(reader))),
            other => Err(DCXError::UnsupportedCodec(*other)),
        };
        codec.map(|codec| Self { size_hint: header.size.get(), codec })
    }

    pub fn size_hint(&self) -> u32 {
        self.size_hint
    }
}

impl<R: Read> Read for DcxReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.codec {
            DcxCompressionCodec::Deflate(compressor) => compressor.read(buf),
            #[allow(unreachable_patterns)]
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DCXError {
    #[error("The metadata header was malformed")]
    MalformedMetadata,
    #[error("The compression format is unsupported: {0:?}")]
    UnsupportedCodec([u8; 4]),
    #[error("Failed to decompress")]
    Decompression,
    #[error("An IO error occurred: {0}")]
    IO(#[from] std::io::Error)
}

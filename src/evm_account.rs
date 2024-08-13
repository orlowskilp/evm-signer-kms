use std::io;

use asn1::{BigInt, BitString, ParseError, Sequence};
use eip2::is_eip2_compat;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};
use sha3::{Digest, Keccak256};

mod eip2;
pub mod kms_key;
pub mod transaction;

use kms_key::KmsKey;
use transaction::free_market_transaction::{
    FreeMarketTransactionSigned, FreeMarketTransactionUnsigned,
};

const PUBLIC_KEY_LENGTH: usize = 64;
const KECCAK_256_LENGTH: usize = 32;
const SIGNATURE_COMPONENT_LENGTH: usize = 32;

type PublicKey = [u8; PUBLIC_KEY_LENGTH];
type Keccak256Digest = [u8; KECCAK_256_LENGTH];
type SignatureComponent = [u8; SIGNATURE_COMPONENT_LENGTH];

fn keccak256_digest(data: &[u8]) -> Keccak256Digest {
    Into::<Keccak256Digest>::into(Keccak256::digest(data))
}

pub struct EvmAccount<'a> {
    pub public_key: PublicKey,
    pub chain_id: u64,
    kms_key: &'a KmsKey<'a>,
}

impl<'a> EvmAccount<'a> {
    fn decode_public_key(public_key_blob: &[u8]) -> Result<PublicKey, io::Error> {
        // Nested closures to have only one error mapping routine
        let public_key = asn1::parse(public_key_blob, |parser| {
            parser.read_element::<Sequence>()?.parse(|parser| {
                let _ = parser.read_element::<Sequence>()?;
                let pk = parser.read_element::<BitString>()?;

                Ok(pk)
            })
        })
        .map_err(|error: ParseError| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse public key: {}", error),
            )
        })?
        .as_bytes();

        // Public key is 65-bytes long, with the first 0x04 byte indicating the EC prefix
        let public_key: PublicKey = public_key[1..].try_into().map_err(|_| {
            // This will never happen for secp256k1 public keys
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid public key format: This was not supposed to happen!",
            )
        })?;

        Ok(public_key)
    }

    pub async fn new(chain_id: u64, kms_key: &'a KmsKey<'a>) -> Result<EvmAccount<'a>, io::Error> {
        let public_key_der = kms_key.get_public_key().await?;
        let public_key = Self::decode_public_key(&public_key_der)?;

        Ok(EvmAccount {
            public_key,
            chain_id,
            kms_key,
        })
    }

    fn to_signature_component(decoded_data: &[u8]) -> SignatureComponent {
        let mut trimmed_data = [0u8; SIGNATURE_COMPONENT_LENGTH];

        trimmed_data.copy_from_slice(if decoded_data.len() > SIGNATURE_COMPONENT_LENGTH {
            &decoded_data[1..]
        } else {
            decoded_data
        });

        trimmed_data
    }

    fn parse_signature(
        signature_der: &[u8],
    ) -> Result<(SignatureComponent, SignatureComponent), io::Error> {
        // Nested closures to have only one error mapping routine
        let (r, s) = asn1::parse(signature_der, |parser| {
            parser.read_element::<Sequence>()?.parse(|parser| {
                let r = parser.read_element::<BigInt>()?;
                let s = parser.read_element::<BigInt>()?;

                Ok((r, s))
            })
        })
        .map_err(|error: ParseError| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse signature: {}", error),
            )
        })?;

        // Remove the leading sign indicator zero byte if present
        let r = Self::to_signature_component(r.as_bytes());
        let s = Self::to_signature_component(s.as_bytes());

        Ok((r, s))
    }

    fn recover_public_key(
        public_key: &[u8],
        digest: &[u8],
        r: &SignatureComponent,
        s: &SignatureComponent,
    ) -> Result<u32, secp256k1::Error> {
        let secp_context = Secp256k1::verification_only();
        // Compact signature is concatenation of 32-byte r and 32-byte s with no headers
        let mut compact_signature = r.to_vec();
        compact_signature.extend_from_slice(s);

        let message = Message::from_digest_slice(digest)?;

        // Possible v values are 0 or 1
        for v in 0..2 {
            let signature =
                RecoverableSignature::from_compact(&compact_signature, RecoveryId::from_i32(v)?)?;

            // Uncompressed public key is 65 bytes long, beginning with 0x04 to indicate it is uncompressed
            let pub_key_uncompressed_bytes = secp_context
                .recover_ecdsa(&message, &signature)?
                .serialize_uncompressed();

            // Drop the 0x04 uncompressed EC prefix
            if pub_key_uncompressed_bytes[1..] == *public_key {
                return Ok(v as u32);
            }
        }

        Err(secp256k1::Error::InvalidPublicKeySum)
    }

    async fn sign_bytes(
        &self,
        digest: &[u8],
        retry_if_not_eip2: bool,
    ) -> Result<(u32, SignatureComponent, SignatureComponent), io::Error> {
        // If s value is larger than Secp256k1 N/2, retry signing until it's less than or equal to N/2
        let (r, s) = loop {
            // TODO: Consider multiple wraps around N/2
            let signature = self.kms_key.sign(digest).await?;
            let (r, s) = Self::parse_signature(&signature)?;

            if !retry_if_not_eip2 {
                break (r, s);
            }

            if is_eip2_compat(s) {
                break (r, s);
            }
        };

        let v = Self::recover_public_key(&self.public_key, digest, &r, &s).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to recover public key: {}", error),
            )
        })?;

        Ok((v, r, s))
    }

    pub async fn sign_transaction(
        &self,
        tx: FreeMarketTransactionUnsigned,
        retry_if_not_eip2: bool,
    ) -> Result<FreeMarketTransactionSigned, io::Error> {
        let digest = keccak256_digest(&tx.encode());
        let signed_bytes_future = self.sign_bytes(&digest, retry_if_not_eip2);

        // Verify if the tx is meant for the same chain as the account is tied to
        if self.chain_id != tx.chain_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Chain ID mismatch between account and transaction",
            ));
        }

        let (v, r, s) = signed_bytes_future.await?;

        Ok(FreeMarketTransactionSigned {
            tx,
            digest,
            v,
            r,
            s,
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{EvmAccount, KECCAK_256_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_COMPONENT_LENGTH};

    const TEST_KEY_DER: [u8; 88] = [
        0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00, 0x04, 0xf9, 0x52, 0xb9, 0x6e, 0xb7, 0xa7,
        0x84, 0x5a, 0xda, 0xbe, 0x93, 0x4b, 0xe3, 0x43, 0x8d, 0x92, 0xe9, 0x97, 0x64, 0x78, 0x56,
        0xdb, 0xc4, 0x89, 0x7c, 0x66, 0x1d, 0x2e, 0x8f, 0x39, 0xbe, 0x7a, 0x27, 0x83, 0x23, 0x47,
        0x42, 0xd4, 0x11, 0xb3, 0xc9, 0xe4, 0x55, 0x4d, 0xb4, 0xc8, 0x66, 0x2a, 0x54, 0x71, 0x60,
        0xf7, 0xee, 0x30, 0xd0, 0xaa, 0x68, 0x00, 0x88, 0xe1, 0xa1, 0xdd, 0x80, 0xc0,
    ];

    const TEST_PUBLIC_KEY: [u8; PUBLIC_KEY_LENGTH] = [
        0xf9, 0x52, 0xb9, 0x6e, 0xb7, 0xa7, 0x84, 0x5a, 0xda, 0xbe, 0x93, 0x4b, 0xe3, 0x43, 0x8d,
        0x92, 0xe9, 0x97, 0x64, 0x78, 0x56, 0xdb, 0xc4, 0x89, 0x7c, 0x66, 0x1d, 0x2e, 0x8f, 0x39,
        0xbe, 0x7a, 0x27, 0x83, 0x23, 0x47, 0x42, 0xd4, 0x11, 0xb3, 0xc9, 0xe4, 0x55, 0x4d, 0xb4,
        0xc8, 0x66, 0x2a, 0x54, 0x71, 0x60, 0xf7, 0xee, 0x30, 0xd0, 0xaa, 0x68, 0x00, 0x88, 0xe1,
        0xa1, 0xdd, 0x80, 0xc0,
    ];

    const TEST_DIGEST: [u8; KECCAK_256_LENGTH] = [
        0x02, 0x6f, 0x61, 0x4e, 0xa0, 0x9e, 0x14, 0x68, 0x28, 0xcb, 0x42, 0xe8, 0xda, 0x55, 0xa5,
        0x9a, 0x90, 0x3b, 0xc6, 0x23, 0x00, 0xa5, 0x27, 0x85, 0xbd, 0xba, 0x8b, 0x94, 0x46, 0xc6,
        0x0c, 0x7d,
    ];

    const TEST_SIGNATURE: [u8; 71] = [
        0x30, 0x45, 0x02, 0x21, 0x00, 0xda, 0x4c, 0x55, 0x29, 0x73, 0x97, 0xee, 0xdf, 0xf0, 0xc4,
        0x3b, 0x3e, 0x32, 0xa2, 0x1b, 0x53, 0x50, 0x89, 0x91, 0xc1, 0xa4, 0xa5, 0x77, 0x6c, 0xc9,
        0x87, 0x48, 0x70, 0xa1, 0xb4, 0x09, 0x0b, 0x02, 0x20, 0x5d, 0x26, 0x16, 0xef, 0x46, 0xbb,
        0x04, 0x28, 0x6f, 0x1e, 0xf8, 0x36, 0x93, 0x01, 0xd8, 0x7a, 0x4a, 0x44, 0x21, 0xf8, 0x22,
        0x77, 0x46, 0xbc, 0x6c, 0x2b, 0x2a, 0x98, 0x0a, 0x3e, 0x27, 0x12,
    ];

    const TEST_R_1: [u8; SIGNATURE_COMPONENT_LENGTH] = [
        0xda, 0x4c, 0x55, 0x29, 0x73, 0x97, 0xee, 0xdf, 0xf0, 0xc4, 0x3b, 0x3e, 0x32, 0xa2, 0x1b,
        0x53, 0x50, 0x89, 0x91, 0xc1, 0xa4, 0xa5, 0x77, 0x6c, 0xc9, 0x87, 0x48, 0x70, 0xa1, 0xb4,
        0x09, 0x0b,
    ];

    const TEST_S_1: [u8; SIGNATURE_COMPONENT_LENGTH] = [
        0x5d, 0x26, 0x16, 0xef, 0x46, 0xbb, 0x04, 0x28, 0x6f, 0x1e, 0xf8, 0x36, 0x93, 0x01, 0xd8,
        0x7a, 0x4a, 0x44, 0x21, 0xf8, 0x22, 0x77, 0x46, 0xbc, 0x6c, 0x2b, 0x2a, 0x98, 0x0a, 0x3e,
        0x27, 0x12,
    ];

    const TEST_R_2: [u8; SIGNATURE_COMPONENT_LENGTH] = [
        0x5e, 0x12, 0x50, 0x05, 0xa0, 0x8e, 0xcd, 0x57, 0x72, 0x81, 0x39, 0x6b, 0x81, 0xb0, 0x57,
        0x20, 0x13, 0xdb, 0xa0, 0x5b, 0x74, 0xfa, 0xc7, 0x79, 0x21, 0xf4, 0x71, 0x9c, 0xf3, 0x7e,
        0x9c, 0xe0,
    ];

    const TEST_S_2: [u8; SIGNATURE_COMPONENT_LENGTH] = [
        0xe9, 0x9f, 0x4f, 0x23, 0x4d, 0x5c, 0x2a, 0x59, 0x0a, 0x4b, 0x0a, 0x07, 0x7d, 0x49, 0x0d,
        0xde, 0x56, 0x4a, 0xbc, 0x14, 0xfc, 0x4e, 0xa5, 0x30, 0x30, 0xa7, 0x14, 0x39, 0x91, 0x0d,
        0xfa, 0x89,
    ];

    #[test]
    fn decode_public_key() {
        let input = TEST_KEY_DER;
        let left = TEST_PUBLIC_KEY.to_vec();

        let right = EvmAccount::decode_public_key(&input).unwrap();

        assert_eq!(left, right);
    }

    #[test]
    fn parse_signature() {
        let input = &TEST_SIGNATURE;

        let (r, s) = EvmAccount::parse_signature(input).unwrap();

        assert_eq!(r, TEST_R_1);
        assert_eq!(s, TEST_S_1);
    }

    #[test]
    fn recover_public_key() {
        let r = TEST_R_2;
        let s = TEST_S_2;
        let input_public_key = TEST_PUBLIC_KEY;
        let input_digest = TEST_DIGEST;

        let left = 0u32;

        let right =
            EvmAccount::recover_public_key(&input_public_key, &input_digest, &r, &s).unwrap();

        assert_eq!(left, right);
    }
}

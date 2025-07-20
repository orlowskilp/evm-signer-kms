mod eip2;

use crate::{
    key::aws_kms::AwsKmsKey,
    transaction::{SignedTransaction, Transaction},
    types::{Keccak256Digest, PublicKey, SIGNATURE_COMPONENT_LENGTH, SignatureComponent},
};
use asn1::{BigInt, BitString, ObjectIdentifier, ParseError, ParseErrorKind, Sequence};
use eip2::reflect_s;
use secp256k1::{
    Message, Secp256k1,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use sha3::{Digest, Keccak256};
use std::{
    cmp::Ordering,
    io::{Error, ErrorKind},
};

/// OIDs for the ASN.1 encoded EC public key
const ASN1_EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
/// OID for the SECP256K1 curve type in ASN.1 encoding
const ASN1_EC_SECP256K1_PK_TYPE_OID: &str = "1.3.132.0.10";

/// Computes the Keccak256 digest of the provided data.
fn keccak256_digest(data: &[u8]) -> Keccak256Digest {
    Keccak256::digest(data).into()
}

/// Representation of EVM account for signing transactions with AWS KMS keys.
pub struct EvmAccount<'a> {
    /// Uncompressed 65-byte public key derived from the private key stored in KMS.
    ///
    /// The key is eagerly decoded during the account instantiation and is used for signature
    /// verification during transaction signing.
    pub public_key: PublicKey,
    /// Reference to the AWS KMS key handke to sign transactions.
    kms_key: &'a AwsKmsKey<'a>,
}

impl<'a> EvmAccount<'a> {
    /// Decodes ASN.1 encoded public key into the uncompressed 65-byte public key.
    fn decode_public_key(public_key_blob: &[u8]) -> Result<PublicKey, Error> {
        asn1::parse(public_key_blob, |parser| {
            parser.read_element::<Sequence>()?.parse(|parser| {
                parser.read_element::<Sequence>()?.parse(|parser| {
                    // Check if the public key is of the expected type
                    let oid = parser.read_element::<ObjectIdentifier>()?.to_string();
                    if oid != ASN1_EC_PUBLIC_KEY_OID {
                        tracing::error!(
                            "Invalid public key OID: expected {}, got {}",
                            ASN1_EC_PUBLIC_KEY_OID,
                            oid
                        );
                        return Err(ParseError::new(ParseErrorKind::InvalidValue));
                    }
                    // Check if the public key is of the expected curve type
                    let curve_oid = parser.read_element::<ObjectIdentifier>()?.to_string();
                    if curve_oid != ASN1_EC_SECP256K1_PK_TYPE_OID {
                        tracing::error!(
                            "Invalid EC curve public key OID: expected {}, got {}",
                            ASN1_EC_SECP256K1_PK_TYPE_OID,
                            curve_oid
                        );
                        return Err(ParseError::new(ParseErrorKind::InvalidValue));
                    }
                    tracing::debug!("Successfully validated secp256k1 public key OID");
                    Ok(())
                })?;
                parser
                    .read_element::<BitString>()
                    // This will not fail as we verified the key type above
                    .map(|bs| bs.as_bytes().try_into().expect("Invalid public key length"))
            })
        })
        .map_err(|err| {
            let msg = format!("Failed to parse public key: {err}");
            tracing::error!(msg);
            Error::new(ErrorKind::InvalidData, msg)
        })
    }

    /// Axiomatic constructor for `EvmAccount` which ties to the provided `KmsKey` instance.
    ///
    /// The constructor eagerly decodes the uncompressed public key from the KMS key i.e. 65-byte
    /// public key prefixed with `0x04`.
    pub async fn new(kms_key: &'a AwsKmsKey<'a>) -> Result<Self, Error> {
        let encoded_public_key = kms_key.get_public_key().await?;
        let public_key = Self::decode_public_key(&encoded_public_key)?;
        tracing::info!("Successfully parsed secp256k1 public key");
        Ok(Self {
            public_key,
            kms_key,
        })
    }

    /// Fits signature coordinate into 32-byte array.
    fn fit_signature_coordinate(decoded_data: &[u8]) -> SignatureComponent {
        // The decoded signature component may be between 31 and 33 bytes long.
        let fitted_data = match decoded_data.len().cmp(&SIGNATURE_COMPONENT_LENGTH) {
            // Trim unnecessary sign indicator
            Ordering::Greater => &decoded_data[1..],
            Ordering::Equal => decoded_data,
            // Pad with leading zero if necessary
            Ordering::Less => &[[0].as_ref(), decoded_data].concat(),
        };
        fitted_data
            .try_into()
            // Safety: We ensure that the length is always SIGNATURE_COMPONENT_LENGTH
            .expect("Invalid signature component length")
    }

    /// Parses the DER-encoded signature into `r` and `s` components.
    fn parse_signature(
        signature_der: &[u8],
    ) -> Result<(SignatureComponent, SignatureComponent), Error> {
        asn1::parse(signature_der, |parser| {
            parser.read_element::<Sequence>()?.parse(|parser| {
                let r = parser.read_element::<BigInt>()?;
                let s = parser.read_element::<BigInt>()?;
                Ok((r.as_bytes(), s.as_bytes()))
            })
        })
        .map(|(r, s)| {
            tracing::debug!("Parsed R: 0x{}", hex::encode(r));
            tracing::debug!("Parsed S: 0x{}", hex::encode(s));
            // Remove the leading sign indicator zero byte if present and reflect s around the y-axis
            (
                Self::fit_signature_coordinate(r),
                reflect_s(Self::fit_signature_coordinate(s)),
            )
        })
        .map_err(|err: ParseError| {
            let msg = format!("Failed to parse signature: {err}");
            tracing::error!(msg);
            Error::new(ErrorKind::InvalidData, msg)
        })
    }

    /// Recovers the public key from the compact signature and message digest, and returns the parity byte.
    fn recover_public_key(
        public_key: PublicKey,
        digest: Keccak256Digest,
        r: &SignatureComponent,
        s: &SignatureComponent,
    ) -> Result<i32, secp256k1::Error> {
        let compact_signature = [r.as_ref(), s.as_ref()].concat();
        let message_digest = Message::from_digest(digest);
        for recid in [RecoveryId::Zero, RecoveryId::One] {
            let recovered_sig = RecoverableSignature::from_compact(&compact_signature, recid)?;
            let recovered_pub_key =
                Secp256k1::verification_only().recover_ecdsa(&message_digest, &recovered_sig)?;
            if recovered_pub_key.serialize_uncompressed() == public_key {
                tracing::debug!(
                    "Recovered public key matches the provided public key with recid: {recid:?}"
                );
                return Ok(recid.into());
            }
        }
        // If we're here, this means that the signature does not match the public key, i.e. key verification failed.
        tracing::error!("Signature verification failed: public key does not match the signature");
        Err(secp256k1::Error::InvalidSignature)
    }

    /// Signs Keccak256 digest with the EVM account's private key.
    async fn sign_digest(
        &self,
        digest: Keccak256Digest,
    ) -> Result<(SignatureComponent, SignatureComponent, u32), Error> {
        let (r, s) = Self::parse_signature(&self.kms_key.sign(&digest).await?)?;
        Self::recover_public_key(self.public_key, digest, &r, &s)
            .map(|v| (r, s, v as u32))
            .map_err(|err| {
                let msg = format!("Failed to recover public key: {err}");
                tracing::error!(msg);
                Error::new(ErrorKind::InvalidData, msg)
            })
    }

    /// Signs the provided transaction with the EVM account's private key.
    ///
    /// The method encodes the unsigned transaction, calculates its digest and signs it with the KMS
    /// private key. It returns a `SignedTransaction` instance with (among others) the `r` and
    /// `s` values, and signature parity.
    pub async fn sign_transaction<T: Transaction>(
        &self,
        tx: T,
    ) -> Result<SignedTransaction<T>, Error> {
        let tx_encoding = tx.encode();
        let digest = keccak256_digest(&tx_encoding);
        self.sign_digest(digest).await.map(|(r, s, v)| {
            tracing::debug!(
                "Successfully signed transaction with digest: 0x{}",
                hex::encode(digest)
            );
            SignedTransaction::new(tx, &tx_encoding, digest, r, s, v)
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::types::{KECCAK_256_LENGTH, UNCOMPRESSED_PUBLIC_KEY_LENGTH};
    use tracing_test::traced_test;

    const TEST_KEY_DER: [u8; 88] = [
        0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00, 0x04, 0xf9, 0x52, 0xb9, 0x6e, 0xb7, 0xa7,
        0x84, 0x5a, 0xda, 0xbe, 0x93, 0x4b, 0xe3, 0x43, 0x8d, 0x92, 0xe9, 0x97, 0x64, 0x78, 0x56,
        0xdb, 0xc4, 0x89, 0x7c, 0x66, 0x1d, 0x2e, 0x8f, 0x39, 0xbe, 0x7a, 0x27, 0x83, 0x23, 0x47,
        0x42, 0xd4, 0x11, 0xb3, 0xc9, 0xe4, 0x55, 0x4d, 0xb4, 0xc8, 0x66, 0x2a, 0x54, 0x71, 0x60,
        0xf7, 0xee, 0x30, 0xd0, 0xaa, 0x68, 0x00, 0x88, 0xe1, 0xa1, 0xdd, 0x80, 0xc0,
    ];

    const TEST_PUBLIC_KEY: [u8; UNCOMPRESSED_PUBLIC_KEY_LENGTH] = [
        0x04, 0xf9, 0x52, 0xb9, 0x6e, 0xb7, 0xa7, 0x84, 0x5a, 0xda, 0xbe, 0x93, 0x4b, 0xe3, 0x43,
        0x8d, 0x92, 0xe9, 0x97, 0x64, 0x78, 0x56, 0xdb, 0xc4, 0x89, 0x7c, 0x66, 0x1d, 0x2e, 0x8f,
        0x39, 0xbe, 0x7a, 0x27, 0x83, 0x23, 0x47, 0x42, 0xd4, 0x11, 0xb3, 0xc9, 0xe4, 0x55, 0x4d,
        0xb4, 0xc8, 0x66, 0x2a, 0x54, 0x71, 0x60, 0xf7, 0xee, 0x30, 0xd0, 0xaa, 0x68, 0x00, 0x88,
        0xe1, 0xa1, 0xdd, 0x80, 0xc0,
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
    #[traced_test]
    fn test_decode_public_key_ok() {
        let input = TEST_KEY_DER;
        let left = TEST_PUBLIC_KEY.to_vec();
        let right = EvmAccount::decode_public_key(&input).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    #[traced_test]
    fn test_parse_signature_ok() {
        let input = &TEST_SIGNATURE;
        let (r, s) = EvmAccount::parse_signature(input).unwrap();
        assert_eq!(r, TEST_R_1);
        assert_eq!(s, TEST_S_1);
    }

    #[test]
    #[traced_test]
    fn test_recover_public_key_ok() {
        let input_public_key = TEST_PUBLIC_KEY;
        let input_digest = TEST_DIGEST;
        let left = 0i32;
        let right =
            EvmAccount::recover_public_key(input_public_key, input_digest, &TEST_R_2, &TEST_S_2)
                .unwrap();
        assert_eq!(left, right);
    }
}

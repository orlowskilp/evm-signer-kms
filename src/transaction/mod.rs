use crate::types::{Keccak256Digest, SignatureComponent};
use access_list::Access;
use hex;
use rlp::{Encodable, RlpStream};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, IntoDeserializer},
    ser::Serializer,
};
use sha3::{Digest, Keccak256};
use std::{
    fmt::Debug,
    io::{Error, ErrorKind},
    string::String,
};

/// Implementation of access list with necessary encoding and serialization logic.
pub mod access_list;
/// Implementation of [`EIP-2930`](https://eips.ethereum.org/EIPS/eip-2930) (type 1) transaction.
pub mod access_list_transaction;
/// Account address logic and serialization.
mod address;
/// Implementation of [`EIP-1559`](https://eips.ethereum.org/EIPS/eip-1559) (type 2) transaction.
pub mod free_market_transaction;
/// Implementation of the original transaction format.
pub mod legacy_transaction;

const HEX_PREFIX: &str = "0x";
const HEX_RADIX: u32 = 16;
const ADDRESS_LENGTH: usize = 20;
// Maximum transaction type value (see EIP-2718).
const MAX_TX_TYPE_ID: u8 = 0x7f;
// Lowest parity value for legacy transactions (see EIP-2).
const LEGACY_TX_MIN_PARITY: u32 = 27;

/// Type alias for convenience.
pub type AccountAddress = [u8; ADDRESS_LENGTH];

/// Trait for all transaction types.
///
/// This trait is used to define the encoding method for all the transaction types.
/// Provides bounds for RLP encoding, comparisons and serialization.
pub trait Transaction:
    // For RLP encoding
    Encodable +
    // For comparisons during testing
    PartialEq +
    // For debugging
    Debug +
    // To satisfy ServiceFn bound required by Lambda runtime
    DeserializeOwned + Serialize
{
    fn encode(&self) -> Vec<u8>;
}

/// Representation of signed transaction.
#[derive(Debug, PartialEq)]
pub struct SignedTransaction<T>
where
    T: Transaction,
{
    /// Transaction type identifier (see [`EIP-2718`](https://eips.ethereum.org/EIPS/eip-2718)).
    pub tx_type: u8,
    /// Unsigned transaction body.
    pub tx: T,
    /// Digest of the transaction payload.
    pub digest: Keccak256Digest,
    /// Parity of the signature.
    pub v: u32,
    /// Signature component `r`, i.e. parameter on x-axis.
    pub r: SignatureComponent,
    /// Signature component `s`, i.e. elliptic curve point.
    pub s: SignatureComponent,
}

impl<T> SignedTransaction<T>
where
    T: Transaction,
{
    /// Creates a new signed transaction.
    ///
    /// The unsigned transaction, transaction digest as well as the signature components are stored
    /// as-is. The encoding is used to determine the transaction type identifier and the parity
    /// value, depending on the transaction type i.e. `v = {27, 28}` for legacy transactions and
    /// `v = {0, 1}` for type 1 and type 2 transactions.
    pub fn new(
        tx: T,
        encoding: &[u8],
        digest: Keccak256Digest,
        r: SignatureComponent,
        s: SignatureComponent,
        v: u32,
    ) -> Self {
        let (tx_type, v) = match encoding[0] {
            tx_type if tx_type < MAX_TX_TYPE_ID => (tx_type, v),
            _ => (0x0, v + LEGACY_TX_MIN_PARITY),
        };

        Self {
            tx_type,
            tx,
            digest,
            r,
            s,
            v,
        }
    }

    /// Encodes the signed transaction using RLP encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream
            .begin_unbounded_list()
            .append(&self.tx)
            .append(&self.v)
            .append(&self.r.as_ref())
            .append(&self.s.as_ref())
            .finalize_unbounded_list();
        let tx_prefix = match self.tx_type {
            0x0 => vec![],
            _ => vec![self.tx_type],
        };
        [tx_prefix.as_ref(), rlp_stream.out().as_ref()].concat()
    }
}

impl<T: Transaction> Serialize for SignedTransaction<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        format!("{}{}", HEX_PREFIX, hex::encode(self.encode())).serialize(serializer)
    }
}

fn hex_data_string_to_bytes(hex_data: &str) -> Result<Vec<u8>, Error> {
    hex::decode(hex_data.trim_start_matches(HEX_PREFIX))
        .map_err(|err| Error::new(ErrorKind::InvalidData, format!("Invalid hex data: {err}")))
}

fn deserialize_hex_data_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    hex::deserialize(
        String::deserialize(deserializer)?
            .trim_start_matches(HEX_PREFIX)
            .to_string()
            .into_deserializer(),
    )
}

fn compute_address_checksum(address: &str) -> Result<String, Error> {
    let address_ascii_lowercase = address.trim_start_matches(HEX_PREFIX).to_ascii_lowercase();
    // Compute the hash of the address and represent it as numerical values
    let hex_hash = hex::encode(Keccak256::digest(&address_ascii_lowercase))
        .chars()
        // Safety: If this errors, then the keccak256 digest is not valid hex, which should never happen
        .map(|ch| u8::from_str_radix(&ch.to_string(), HEX_RADIX).expect("Invalid hex character"))
        .collect::<Vec<_>>();
    // Iterate over the address and hash, and construct the checksummed address according to EIP-55
    address_ascii_lowercase.chars().zip(hex_hash).try_fold(
        HEX_PREFIX.to_string(),
        |mut address_checksum, (nibble, hashed_address_nibble)| {
            address_checksum.push(match nibble {
                '0'..='9' => nibble,
                'a'..='f' if hashed_address_nibble > 7 => nibble.to_ascii_uppercase(),
                'a'..='f' => nibble,
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Invalid character in address: {nibble}"),
                    ));
                }
            });
            Ok(address_checksum)
        },
    )
}

fn validate_address_checksum(address: &str) -> bool {
    // If the address is all in lowercase, this means no checksum was applied and no validation is
    // needed. This is acceptable, however a warning should be logged.
    if address == address.to_ascii_lowercase() {
        return true;
    }
    // Otherwise strict chgecksum validation is required.
    match compute_address_checksum(address) {
        Ok(checksum) => checksum == address,
        Err(_) => false,
    }
}

fn deserialize_address_string_option<'de, D>(
    deserializer: D,
) -> Result<Option<AccountAddress>, D::Error>
where
    D: Deserializer<'de>,
{
    let address_string = String::deserialize(deserializer)?;
    if !validate_address_checksum(&address_string) {
        return Err(de::Error::custom("Invalid address checksum"));
    }

    let address_bytes = hex_data_string_to_bytes(&address_string)
        .map_err(|err| de::Error::custom(format!("Failed to deserialize address: {err}")))?;
    if address_bytes.is_empty() {
        return Ok(None);
    }

    address_bytes
        // Checks whether address is of proper length
        .try_into()
        .map(Some)
        .map_err(|_| de::Error::custom("Invalid address length"))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const TEST_ADDR_STR_1: &str = "0xa9d89186cAA663C8Ef0352Fd1Db3596280625573";
    const TEST_ADDR_STR_2: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    const TEST_ADDR_STR_3: &str = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";

    const TEST_ADDR_BYTES: AccountAddress = [
        0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3, 0x59,
        0x62, 0x80, 0x62, 0x55, 0x73,
    ];

    #[test]
    fn evm_address_to_bytes_test() {
        let input = TEST_ADDR_STR_1;
        let left = TEST_ADDR_BYTES.to_vec();

        let right = hex_data_string_to_bytes(input).unwrap();

        assert_eq!(left, right);
    }

    #[test]
    fn validate_recipient_address_test_1_succeed() {
        let input = TEST_ADDR_STR_1;

        assert!(validate_address_checksum(input));
    }

    #[test]
    fn validate_recipient_address_test_2_succeed() {
        let input = TEST_ADDR_STR_2;

        assert!(validate_address_checksum(input));
    }

    #[test]
    fn validate_recipient_address_test_3_succeed() {
        let input = TEST_ADDR_STR_3;

        assert!(validate_address_checksum(input));
    }

    #[test]
    fn validate_recipient_address_test_1_no_checksum_succeed() {
        let input = TEST_ADDR_STR_1.to_ascii_lowercase();

        assert!(validate_address_checksum(&input));
    }

    #[test]
    fn validate_recipient_address_test_2_no_checksum_succeed() {
        let input = TEST_ADDR_STR_2.to_ascii_lowercase();

        assert!(validate_address_checksum(&input));
    }

    #[test]
    fn validate_recipient_address_test_3_no_checksum_succeed() {
        let input = TEST_ADDR_STR_3.to_ascii_lowercase();

        assert!(validate_address_checksum(&input));
    }

    #[test]
    #[should_panic]
    fn validate_recipient_address_test_1_fail() {
        let input = "0xA9d89186caA663C8Ef0352Fd1Db3596280625573";

        assert!(validate_address_checksum(input));
    }

    #[test]
    #[should_panic]
    fn validate_recipient_address_test_2_fail() {
        let input = "0x5aAeb6053F3E94c9b9A09F33669435E7Ef1BeAed";

        assert!(validate_address_checksum(input));
    }

    #[test]
    #[should_panic]
    fn validate_recipient_address_test_3_fail() {
        let input = "0xfb6916095CA1df60bB79Ce92cE3Ea74c37c5d359";

        assert!(validate_address_checksum(input));
    }
}

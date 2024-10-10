use std::{
    fmt::{Debug, Write},
    io::{Error, ErrorKind},
    string::String,
};

use rlp::{Encodable, RlpStream};
use serde::{Deserialize, Deserializer, Serialize};

/// Implementation of access list with necessary encoding and serialization logic.
pub mod access_list;
/// Implementation of [`EIP-2930`](https://eips.ethereum.org/EIPS/eip-2930) (type 1) transaction.
pub mod access_list_transaction;
/// Implementation of [`EIP-1559`](https://eips.ethereum.org/EIPS/eip-1559) (type 2) transaction.
pub mod free_market_transaction;
/// Implementation of the original transaction format.
pub mod legacy_transaction;

use crate::evm_account::{Keccak256Digest, SignatureComponent};
use access_list::Access;

const HEX_PREFIX: &str = "0x";
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
    serde::de::DeserializeOwned + serde::ser::Serialize
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
        v: u32,
        r: SignatureComponent,
        s: SignatureComponent,
    ) -> Self {
        let (tx_type, v) = if encoding[0] < MAX_TX_TYPE_ID {
            (encoding[0], v)
        } else {
            (0x0, v + LEGACY_TX_MIN_PARITY)
        };

        Self {
            tx_type,
            tx,
            digest,
            v,
            r,
            s,
        }
    }

    /// Encodes the signed transaction using RLP encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream
            .begin_unbounded_list()
            .append(&self.tx)
            .append(&self.v)
            .append(&self.r.as_slice())
            .append(&self.s.as_slice())
            .finalize_unbounded_list();

        let mut rlp_bytes = rlp_stream.out().to_vec();

        if self.tx_type > 0x0 {
            rlp_bytes.insert(0, self.tx_type);
        }

        rlp_bytes
    }
}

impl<T> Serialize for SignedTransaction<T>
where
    T: Transaction,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.encode()
            .iter()
            .fold(HEX_PREFIX.to_string(), |mut output, byte| {
                let _ = write!(output, "{:02x}", byte);
                output
            })
            .serialize(serializer)
    }
}

fn hex_data_string_to_bytes(hex_data: &str) -> Result<Vec<u8>, Error> {
    const HEX_RADIX: u32 = 16;
    const STEP_BY: usize = 2;

    let hex_data = hex_data.trim_start_matches(HEX_PREFIX);

    (0..hex_data.len())
        .step_by(STEP_BY)
        .map(|i| {
            u8::from_str_radix(&hex_data[i..i + STEP_BY], HEX_RADIX)
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))
        })
        .collect()
}

fn deserialize_hex_data_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string = String::deserialize(deserializer)?;

    hex_data_string_to_bytes(&hex_string).map_err(|error| {
        serde::de::Error::custom(format!("Failed to deserialize hex data: {}", error))
    })
}

fn deserialize_address_string<'de, D>(deserializer: D) -> Result<AccountAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let address_string = String::deserialize(deserializer)?;

    hex_data_string_to_bytes(&address_string)
        .map_err(|error| {
            serde::de::Error::custom(format!("Failed to deserialize address: {}", error))
        })?
        // Checks whether address is of proper length
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid address length"))
}

fn deserialize_address_string_option<'de, D>(
    deserializer: D,
) -> Result<Option<AccountAddress>, D::Error>
where
    D: Deserializer<'de>,
{
    let address_string = String::deserialize(deserializer)?;

    let address_bytes = hex_data_string_to_bytes(&address_string).map_err(|error| {
        serde::de::Error::custom(format!("Failed to deserialize address: {}", error))
    })?;

    if address_bytes.is_empty() {
        return Ok(None);
    }

    let address = address_bytes
        // Checks whether address is of proper length
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid address length"))?;

    Ok(Some(address))
}

#[cfg(test)]
mod unit_tests {
    use super::{hex_data_string_to_bytes, AccountAddress};

    const TEST_ADDR_STR: &str = "0xa9d89186cAA663C8Ef0352Fd1Db3596280625573";

    const TEST_ADDR_BYTES: AccountAddress = [
        0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3, 0x59,
        0x62, 0x80, 0x62, 0x55, 0x73,
    ];

    #[test]
    fn evm_address_to_bytes_test() {
        let input = TEST_ADDR_STR;
        let left = TEST_ADDR_BYTES.to_vec();

        let right = hex_data_string_to_bytes(input).unwrap();

        assert_eq!(left, right);
    }
}

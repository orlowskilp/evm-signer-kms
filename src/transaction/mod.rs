use crate::{
    transaction::address::AccountAddress,
    types::{Keccak256Digest, SignatureComponent},
};
use access_list::Access;
use hex;
use rlp::{Encodable, RlpStream};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as DeError, IntoDeserializer},
    ser::Serializer,
};
use std::{fmt::Debug, string::String};

/// Implementation of access list with necessary encoding and serialization logic.
pub mod access_list;
/// Implementation of [`EIP-2930`](https://eips.ethereum.org/EIPS/eip-2930) (type 1) transaction.
pub mod access_list_transaction;
/// Account address logic and serialization.
pub mod address;
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

/// Trait for all transaction types.
///
/// This trait is used to define the encoding method for all the transaction types.
/// Provides bounds for RLP encoding, comparisons and deserialization.
pub trait Transaction:
    Clone +
    // For RLP encoding
    Encodable +
    // For comparisons during testing
    PartialEq +
    // For debugging
    Debug +
    // For deserialization
    DeserializeOwned
{
    /// Encodes the transaction into a byte vector using RLP encoding.
    fn encode(&self) -> Vec<u8>;
}

/// Representation of signed transaction.
#[derive(Debug, PartialEq)]
pub struct SignedTransaction<T: Transaction> {
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

impl<T: Transaction> SignedTransaction<T> {
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

/// Deserializer function for signed transactions, stripping the `0x` prefix from hex strings.
fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    hex::deserialize(
        String::deserialize(deserializer)?
            .trim_start_matches(HEX_PREFIX)
            .to_string()
            .into_deserializer(),
    )
}

/// Fits bytes into sized types.
fn fit_bytes<'de, T, D>(bytes: &[u8]) -> Result<T, D::Error>
where
    T: TryFrom<Vec<u8>, Error = Vec<u8>>,
    D: Deserializer<'de>,
{
    bytes
        .to_vec()
        .try_into()
        .map_err(|v: Vec<_>| D::Error::custom(format!("Got {} bytes", v.len())))
}

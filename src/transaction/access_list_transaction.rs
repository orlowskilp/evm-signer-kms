use super::{AccountAddress, Transaction, access_list::Access};
use rlp::{Encodable, RlpStream};
use serde::Deserialize;

const EIP_2930_TX_TYPE_ID: u8 = 0x01;

/// Represents an access list (i.e. type 1) transaction.
///
/// Type 1 transaction format for transactions with an optional access list as defined in
/// [`EIP-2930`](https://eips.ethereum.org/EIPS/eip-2930).
#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListTransaction {
    /// Chain ID of the network to prevent replay attacks
    /// (see [`EIP-155`](https://eips.ethereum.org/EIPS/eip-155)).
    pub chain_id: u64,
    /// Sequence number of transaction from the account.
    pub nonce: u128,
    /// Gas price in wei (see
    /// [this article](https://ethereum.org/en/developers/docs/gas)).
    pub gas_price: u128,
    /// The maximum amount of gas that can be used by the transaction.
    pub gas_limit: u128,
    /// The address of the recipient of the transaction or `None` for smart contract deployment.
    pub to: Option<AccountAddress>,
    /// The amount of wei to transfer to the recipient.
    pub value: u128,
    /// Transaction data to be sent with the transaction (see
    /// [this article](https://ethereum.org/en/developers/docs/transactions/#the-data-field)).
    #[serde(with = "super")]
    pub data: Vec<u8>,
    /// List of addresses and storage keys that the transaction plans to access.
    pub access_list: Vec<Access>,
}

impl Transaction for AccessListTransaction {
    fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream
            .begin_unbounded_list()
            .append(self)
            .finalize_unbounded_list();
        [[EIP_2930_TX_TYPE_ID].as_ref(), rlp_stream.out().as_ref()].concat()
    }
}

impl Encodable for AccessListTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        let to = match &self.to {
            Some(to) => to.as_slice(),
            None => &[],
        };

        s.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.gas_price)
            .append(&self.gas_limit)
            .append(&to)
            .append(&self.value)
            .append(&self.data)
            .begin_unbounded_list();
        self.access_list.iter().for_each(|key| {
            s.append(key);
        });
        s.finalize_unbounded_list()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const TEST_ADDRESS: [u8; 20] = [
        0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59, 0x8f, 0xcf, 0xfd, 0x61,
        0xc4, 0x82, 0x99, 0xf1, 0x2f,
    ];

    const TEST_ENCODING: [u8; 71] = [
        0x01, 0xf8, 0x44, 0x83, 0x06, 0x6e, 0xee, 0x05, 0x85, 0x17, 0x48, 0x76, 0xe8, 0x00, 0x82,
        0x52, 0x08, 0x94, 0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59, 0x8f,
        0xcf, 0xfd, 0x61, 0xc4, 0x82, 0x99, 0xf1, 0x2f, 0x87, 0x23, 0x86, 0xf2, 0x6f, 0xc1, 0x00,
        0x00, 0x80, 0xd7, 0xd6, 0x94, 0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f, 0xde, 0x78,
        0x3f, 0xcc, 0x1c, 0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13, 0xc0,
    ];

    #[test]
    fn encode_valid_tx_01_succeed() {
        let left = TEST_ENCODING.to_vec();
        let right = AccessListTransaction {
            chain_id: 421614,
            nonce: 5,
            gas_price: 100_000_000_000,
            gas_limit: 21_000,
            to: Some(AccountAddress::from(TEST_ADDRESS)),
            value: 10_000_000_000_000_000,
            data: vec![],
            access_list: vec![Access {
                address: AccountAddress::from([
                    0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f, 0xde, 0x78, 0x3f, 0xcc, 0x1c,
                    0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13,
                ]),
                storage_keys: vec![],
            }],
        }
        .encode();

        assert_eq!(left, right);
    }
}

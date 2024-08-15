use rlp::{Encodable, RlpStream};
use serde::{Deserialize, Serialize};

use super::{
    access_list::Access, deserialize_address_string, deserialize_hex_data_string, AccountAddress,
    Transaction,
};

const EIP_2930_TX_TYPE_ID: u8 = 0x01;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListTransaction {
    pub chain_id: u64,
    pub nonce: u128,
    pub gas_price: u128,
    pub gas_limit: u128,
    #[serde(deserialize_with = "deserialize_address_string")]
    pub to: AccountAddress,
    pub value: u128,
    #[serde(deserialize_with = "deserialize_hex_data_string")]
    pub data: Vec<u8>,
    pub access_list: Vec<Access>,
}

impl Transaction for AccessListTransaction {
    fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream
            .begin_unbounded_list()
            .append(self)
            .finalize_unbounded_list();

        let mut rlp_bytes = rlp_stream.out().to_vec();
        rlp_bytes.insert(0, EIP_2930_TX_TYPE_ID);

        rlp_bytes
    }
}

impl Encodable for AccessListTransaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.gas_price)
            .append(&self.gas_limit)
            .append(&self.to.as_slice())
            .append(&self.value)
            .append(&self.data)
            .begin_unbounded_list();
        for access in &self.access_list {
            s.append(access);
        }
        s.finalize_unbounded_list()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const TEST_ADDRESS: AccountAddress = [
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
            to: TEST_ADDRESS,
            value: 10_000_000_000_000_000,
            data: vec![],
            access_list: vec![Access {
                address: [
                    0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f, 0xde, 0x78, 0x3f, 0xcc, 0x1c,
                    0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13,
                ],
                storage_keys: vec![],
            }],
        }
        .encode();

        assert_eq!(left, right);
    }
}

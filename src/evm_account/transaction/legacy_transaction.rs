use rlp::Encodable;
use serde::{Deserialize, Serialize};

use super::{
    deserialize_address_string_option, deserialize_hex_data_string, AccountAddress, Transaction,
};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyTransaction {
    pub nonce: u128,
    pub gas_price: u128,
    pub gas_limit: u128,
    #[serde(deserialize_with = "deserialize_address_string_option")]
    pub to: Option<AccountAddress>,
    pub value: u128,
    #[serde(deserialize_with = "deserialize_hex_data_string")]
    pub data: Vec<u8>,
}

impl Transaction for LegacyTransaction {
    fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = rlp::RlpStream::new();
        rlp_stream
            .begin_unbounded_list()
            .append(self)
            .finalize_unbounded_list();

        rlp_stream.out().to_vec()
    }
}

impl Encodable for LegacyTransaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        let to = match &self.to {
            Some(to) => to.as_slice(),
            None => &[],
        };

        s.append(&self.nonce)
            .append(&self.gas_price)
            .append(&self.gas_limit)
            .append(&to)
            .append(&self.value)
            .append(&self.data);
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const TEST_ADDRESS: AccountAddress = [
        0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59, 0x8f, 0xcf, 0xfd, 0x61,
        0xc4, 0x82, 0x99, 0xf1, 0x2f,
    ];

    const TEST_ENCODING: [u8; 41] = [
        0xe8, 0x05, 0x85, 0x17, 0x48, 0x76, 0xe8, 0x00, 0x82, 0x52, 0x08, 0x94, 0x70, 0xad, 0x75,
        0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59, 0x8f, 0xcf, 0xfd, 0x61, 0xc4, 0x82, 0x99,
        0xf1, 0x2f, 0x87, 0x23, 0x86, 0xf2, 0x6f, 0xc1, 0x00, 0x00, 0x80,
    ];

    #[test]
    fn encode_valid_tx_01_succeed() {
        let left = TEST_ENCODING.to_vec();
        let right = LegacyTransaction {
            nonce: 5,
            gas_price: 100_000_000_000,
            gas_limit: 21_000,
            to: Some(TEST_ADDRESS),
            value: 10_000_000_000_000_000,
            data: vec![],
        }
        .encode();

        assert_eq!(left, right);
    }
}

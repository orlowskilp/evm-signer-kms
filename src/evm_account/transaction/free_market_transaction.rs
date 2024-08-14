use std::fmt::Write;

use rlp::{Encodable, RlpStream};
use serde::{Deserialize, Serialize};

use crate::evm_account::transaction::{
    deserialize_address_string, deserialize_hex_data_string, Access, AccountAddress,
    Keccak256Digest, SignatureComponent, Transaction, EIP_1559_TX_TYPE_ID, HEX_PREFIX,
};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeMarketTransactionUnsigned {
    pub gas_limit: u128,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub chain_id: u64,
    pub nonce: u128,
    // FIXME: This may be empty for contract creation tx
    #[serde(deserialize_with = "deserialize_address_string")]
    pub to: AccountAddress,
    pub value: u128,
    #[serde(deserialize_with = "deserialize_hex_data_string")]
    pub data: Vec<u8>,
    pub access_list: Vec<Access>,
}

impl Transaction for FreeMarketTransactionUnsigned {
    fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream
            .begin_unbounded_list()
            .append(self)
            .finalize_unbounded_list();

        let mut rlp_bytes = rlp_stream.out().to_vec();
        rlp_bytes.insert(0, EIP_1559_TX_TYPE_ID);

        rlp_bytes
    }
}

impl Encodable for FreeMarketTransactionUnsigned {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.max_priority_fee_per_gas)
            .append(&self.max_fee_per_gas)
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

#[derive(Debug, PartialEq)]
pub struct FreeMarketTransactionSigned<T>
where
    T: Transaction,
{
    pub tx: T,
    pub digest: Keccak256Digest,
    pub v: u32,
    pub r: SignatureComponent,
    pub s: SignatureComponent,
}

impl<T> FreeMarketTransactionSigned<T>
where
    T: Transaction,
{
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
        rlp_bytes.insert(0, EIP_1559_TX_TYPE_ID);

        rlp_bytes
    }
}

impl<T> Serialize for FreeMarketTransactionSigned<T>
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

#[cfg(test)]
mod unit_tests {
    use super::{Access, AccountAddress, FreeMarketTransactionUnsigned, Transaction};

    const TEST_ADDRESS: AccountAddress = [
        0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59, 0x8f, 0xcf, 0xfd, 0x61,
        0xc4, 0x82, 0x99, 0xf1, 0x2f,
    ];

    const TEST_ENCODING_NO_ACCESS_LIST: [u8; 49] = [
        0x02, 0xef, 0x01, 0x80, 0x84, 0xb2, 0xd0, 0x5e, 0x00, 0x85, 0x17, 0x48, 0x76, 0xe8, 0x00,
        0x82, 0x52, 0x08, 0x94, 0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59,
        0x8f, 0xcf, 0xfd, 0x61, 0xc4, 0x82, 0x99, 0xf1, 0x2f, 0x87, 0x23, 0x86, 0xf2, 0x6f, 0xc1,
        0x00, 0x00, 0x80, 0xc0,
    ];

    const TEST_ENCODING_WITH_ACCESS_LIST_1: [u8; 73] = [
        0x02, 0xf8, 0x46, 0x01, 0x80, 0x84, 0xb2, 0xd0, 0x5e, 0x00, 0x85, 0x17, 0x48, 0x76, 0xe8,
        0x00, 0x82, 0x52, 0x08, 0x94, 0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf,
        0x59, 0x8f, 0xcf, 0xfd, 0x61, 0xc4, 0x82, 0x99, 0xf1, 0x2f, 0x87, 0x23, 0x86, 0xf2, 0x6f,
        0xc1, 0x00, 0x00, 0x80, 0xd7, 0xd6, 0x94, 0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f,
        0xde, 0x78, 0x3f, 0xcc, 0x1c, 0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13, 0xc0,
    ];

    const TEST_ENCODING_WITH_ACCESS_LIST_2: [u8; 165] = [
        0x02, 0xf8, 0xa2, 0x01, 0x80, 0x84, 0xb2, 0xd0, 0x5e, 0x00, 0x85, 0x17, 0x48, 0x76, 0xe8,
        0x00, 0x82, 0x52, 0x08, 0x94, 0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf,
        0x59, 0x8f, 0xcf, 0xfd, 0x61, 0xc4, 0x82, 0x99, 0xf1, 0x2f, 0x87, 0x23, 0x86, 0xf2, 0x6f,
        0xc1, 0x00, 0x00, 0x80, 0xf8, 0x72, 0xf8, 0x59, 0x94, 0xde, 0x0b, 0x29, 0x56, 0x69, 0xa9,
        0xfd, 0x93, 0xd5, 0xf2, 0x8d, 0x9e, 0xc8, 0x5e, 0x40, 0xf4, 0xcb, 0x69, 0x7b, 0xae, 0xf8,
        0x42, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd6, 0x94, 0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98,
        0x12, 0x3f, 0xde, 0x78, 0x3f, 0xcc, 0x1c, 0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13, 0xc0,
    ];

    #[test]
    fn unsigned_tx_encode_no_access_list() {
        let left = TEST_ENCODING_NO_ACCESS_LIST.to_vec();

        let right = FreeMarketTransactionUnsigned {
            gas_limit: 21_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 3_000_000_000,
            chain_id: 1,
            nonce: 0,
            to: TEST_ADDRESS,
            value: 10_000_000_000_000_000,
            data: vec![],
            access_list: vec![],
        }
        .encode();

        assert_eq!(left, right);
    }

    #[test]
    fn unsigned_tx_encode_with_access_list_1() {
        let left = TEST_ENCODING_WITH_ACCESS_LIST_1.to_vec();

        let right = FreeMarketTransactionUnsigned {
            gas_limit: 21_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 3_000_000_000,
            chain_id: 1,
            nonce: 0,
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

    #[test]
    fn unsigned_tx_encode_with_access_list_2() {
        let left = TEST_ENCODING_WITH_ACCESS_LIST_2.to_vec();

        let right = FreeMarketTransactionUnsigned {
            gas_limit: 21_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 3_000_000_000,
            chain_id: 1,
            nonce: 0,
            to: TEST_ADDRESS,
            value: 10_000_000_000_000_000,
            data: vec![],
            access_list: vec![
                Access {
                    address: [
                        0xde, 0x0b, 0x29, 0x56, 0x69, 0xa9, 0xfd, 0x93, 0xd5, 0xf2, 0x8d, 0x9e,
                        0xc8, 0x5e, 0x40, 0xf4, 0xcb, 0x69, 0x7b, 0xae,
                    ],
                    storage_keys: vec![
                        [
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                        ],
                        [
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
                        ],
                    ],
                },
                Access {
                    address: [
                        0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f, 0xde, 0x78, 0x3f, 0xcc,
                        0x1c, 0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13,
                    ],
                    storage_keys: vec![],
                },
            ],
        }
        .encode();

        assert_eq!(left, right);
    }
}

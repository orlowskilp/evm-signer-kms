use std::fmt::Write;

use rlp::RlpStream;
use serde::{Deserialize, Serialize};

use crate::evm_account::transaction::{
    deserialize_address_string, deserialize_hex_data_string, AccountAddress, Keccak256Digest,
    SignatureComponent, EIP_1559_TX_TYPE_ID, HEX_PREFIX,
};

fn build_payload_rlp_stream(stream: &mut RlpStream, tx: &FreeMarketTransactionUnsigned) {
    // FIXME: This is a temporary solution to set the access list to empty
    const TEMP_ACCESS_LIST_RLP_ENCODING: [u8; 1] = [0xc0];

    stream
        .append(&tx.chain_id)
        .append(&tx.nonce)
        .append(&tx.max_priority_fee_per_gas)
        .append(&tx.max_fee_per_gas)
        .append(&tx.gas_limit)
        .append(&tx.to.as_slice())
        .append(&tx.value)
        .append(&tx.data)
        // NOTE: Manually set the access list to empty. Fix this in the future
        .append_raw(
            &TEMP_ACCESS_LIST_RLP_ENCODING,
            TEMP_ACCESS_LIST_RLP_ENCODING.len(),
        );
}

#[derive(Debug, Deserialize, PartialEq)]
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
    // TODO: AccessList abstraction will be added in the future
    pub access_list: Vec<u8>,
}

impl FreeMarketTransactionUnsigned {
    pub fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_unbounded_list();
        build_payload_rlp_stream(&mut rlp_stream, self);
        rlp_stream.finalize_unbounded_list();

        let mut rlp_bytes = rlp_stream.out().to_vec();
        rlp_bytes.insert(0, EIP_1559_TX_TYPE_ID);

        rlp_bytes
    }
}

#[derive(Debug, PartialEq)]
pub struct FreeMarketTransactionSigned {
    pub tx: FreeMarketTransactionUnsigned,
    pub digest: Keccak256Digest,
    pub v: u32,
    pub r: SignatureComponent,
    pub s: SignatureComponent,
}

impl FreeMarketTransactionSigned {
    pub fn encode(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_unbounded_list();
        build_payload_rlp_stream(&mut rlp_stream, &self.tx);
        rlp_stream
            .append(&self.v)
            .append(&self.r.as_slice())
            .append(&self.s.as_slice());
        rlp_stream.finalize_unbounded_list();

        let mut rlp_bytes = rlp_stream.out().to_vec();
        rlp_bytes.insert(0, EIP_1559_TX_TYPE_ID);

        rlp_bytes
    }
}

impl Serialize for FreeMarketTransactionSigned {
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
    use super::{AccountAddress, FreeMarketTransactionUnsigned};

    const TEST_ADDRESS: AccountAddress = [
        0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59, 0x8f, 0xcf, 0xfd, 0x61,
        0xc4, 0x82, 0x99, 0xf1, 0x2f,
    ];

    const TEST_ENCODING: [u8; 49] = [
        0x02, 0xef, 0x01, 0x80, 0x84, 0xb2, 0xd0, 0x5e, 0x00, 0x85, 0x17, 0x48, 0x76, 0xe8, 0x00,
        0x82, 0x52, 0x08, 0x94, 0x70, 0xad, 0x75, 0x4f, 0xf6, 0x70, 0x07, 0x74, 0x11, 0xdf, 0x59,
        0x8f, 0xcf, 0xfd, 0x61, 0xc4, 0x82, 0x99, 0xf1, 0x2f, 0x87, 0x23, 0x86, 0xf2, 0x6f, 0xc1,
        0x00, 0x00, 0x80, 0xc0,
    ];

    #[test]
    fn unsigned_tx_encode() {
        let left = TEST_ENCODING.to_vec();

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
}

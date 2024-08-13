use ethnum::U256;

use crate::evm_account::SignatureComponent;

const SECP_256K1_N: U256 = U256([
    0xffffffff_ffffffff_ffffffff_fffffffe,
    0xbaaedce6_af48a03b_bfd25e8c_d0364141,
]);

// AWS KMS Secp256k1 signatures may have values exceeding Secp256k1 N.
// Not only will these signatures be rejected by the EVM, but they cannot be
// fixed by wrapping them around N/2.
pub fn is_eip2_compat(s: SignatureComponent) -> bool {
    let s_u256 = U256::from_be_bytes(s);

    s_u256 <= SECP_256K1_N / 2
}

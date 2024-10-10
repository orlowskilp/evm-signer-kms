use ethnum::U256;

use crate::evm_account::SignatureComponent;

const SECP_256K1_N: U256 = U256([
    // NOTE: The order of words is reversed
    0xbaaedce6_af48a03b_bfd25e8c_d0364141,
    0xffffffff_ffffffff_ffffffff_fffffffe,
]);

/// Wraps the `s` value of signature around x-axis.
///
/// See [`EIP-2`](https://eips.ethereum.org/EIPS/eip-2) for details. Moved to separate module to
/// keep Ethereum specific dependencies in one place.
pub fn wrap_s(component: SignatureComponent) -> SignatureComponent {
    let mut s_u256 = U256::from_be_bytes(component);

    // TODO: Remove after sufficient testing and monitoring
    assert!(s_u256 <= SECP_256K1_N, "⚠️ Maximum curve value exceeded‼️");

    if s_u256 >= SECP_256K1_N / 2 {
        s_u256 = SECP_256K1_N - s_u256;
    }

    s_u256.to_be_bytes()
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_wrap_s_max_secp_256k1_n() {
        let input = SignatureComponent::try_from(SECP_256K1_N.to_be_bytes()).unwrap();

        let left = [0x0; 32];
        let right = wrap_s(input);

        assert_eq!(left, right);
    }

    #[test]
    #[should_panic]
    fn test_wrap_s_max_exceeded() {
        let input = SignatureComponent::try_from((SECP_256K1_N + 1).to_be_bytes()).unwrap();

        wrap_s(input);
    }

    #[test]
    fn test_wrap_s_less_than_max() {
        let input = SignatureComponent::try_from((SECP_256K1_N - 1).to_be_bytes()).unwrap();

        // The byte order is reversed
        let left = U256([0x01, 0x00]).to_be_bytes();
        let right = wrap_s(input);

        assert_eq!(left, right);
    }

    #[test]
    fn test_wrap_s_one() {
        let input = SignatureComponent::try_from(U256([0x01, 0x00]).to_be_bytes()).unwrap();

        // The byte order is reversed
        let left = U256([0x01, 0x00]).to_be_bytes();
        let right = wrap_s(input);

        assert_eq!(left, right);
    }
}

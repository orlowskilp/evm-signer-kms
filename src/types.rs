pub(crate) const PUBLIC_KEY_LENGTH: usize = 64;
pub(crate) const KECCAK_256_LENGTH: usize = 32;
pub(crate) const SIGNATURE_COMPONENT_LENGTH: usize = 32;

pub(crate) type PublicKey = [u8; PUBLIC_KEY_LENGTH];
pub type Keccak256Digest = [u8; KECCAK_256_LENGTH];
pub type SignatureComponent = [u8; SIGNATURE_COMPONENT_LENGTH];

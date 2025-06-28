pub(crate) const UNCOMPRESSED_PUBLIC_KEY_LENGTH: usize = 65;
pub(crate) const KECCAK_256_LENGTH: usize = 32;
pub(crate) const SIGNATURE_COMPONENT_LENGTH: usize = 32;

pub(crate) type PublicKey = [u8; UNCOMPRESSED_PUBLIC_KEY_LENGTH];
pub(crate) type Keccak256Digest = [u8; KECCAK_256_LENGTH];
pub(crate) type SignatureComponent = [u8; SIGNATURE_COMPONENT_LENGTH];

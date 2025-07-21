use anyhow::{Result, bail};
use evm_signer_kms::{
    account::EvmAccount, key::aws_kms::AwsKmsKey,
    transaction::access_list_transaction::AccessListTransaction,
};
use std::env;

// Name of the environment variable that contains the KMS key ID
const KMS_KEY_ID_VAR_NAME: &str = "KMS_KEY_ID";
// Example EIP-2930 transaction JSON
const ACCESS_LIST_TX_JSON: &str = r#"
{
    "gasLimit": 21000,
    "gasPrice": 100000000000,
    "chainId": 11155111,
    "nonce": 0,
    "to": "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    "value": 10000000000000000,
    "data": "",
    "accessList": [
        [
            "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
            [
                "0x0000000000000000000000000000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000000000000000000000000000007"
            ]
        ],
        [
            "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
            []
        ]
    ]
}
"#;

// Communication with AWS endpoint is asynchronous, so we need to use async main function
#[tokio::main]
async fn main() -> Result<()> {
    // Get KMS key ID from environment variable
    let kms_key_id = env::var(KMS_KEY_ID_VAR_NAME).or_else(|_| {
        bail!("Not set: {KMS_KEY_ID_VAR_NAME}");
    })?;

    // Create a new KMS key
    let kms_key = &AwsKmsKey::new(&kms_key_id).await;
    // Create a new EVM account
    let evm_account = EvmAccount::new(kms_key).await.or_else(|err| {
        bail!("Create EVM account: {err}");
    })?;

    // Create a new unsigned EIP-2930 transaction
    let unigned_tx =
        serde_json::from_str::<AccessListTransaction>(ACCESS_LIST_TX_JSON).or_else(|err| {
            bail!("Parse transaction JSON: {err}");
        })?;

    // Sign the transaction using EVM account
    let signed_tx = evm_account
        .sign_transaction(unigned_tx)
        .await
        .or_else(|err| {
            bail!("Sign transaction: {err}");
        })?;

    // Use the provided string serialization to get the signed transaction encoding.
    let signed_tx_encoding = serde_plain::to_string(&signed_tx).or_else(|err| {
        bail!("Serialize signed transaction: {err}");
    })?;

    println!("Encoded signe type-1 transaction: {signed_tx_encoding}");

    Ok(())
}

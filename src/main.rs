//! Implements a prototype smart contract wallet that uses a p256 signature to approve transactions.
//! Warning: this code is experimental and has not been audited.

// Only run this as a WASM if the export-abi feature is not set.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

/// Initializes a custom, global allocator for Rust programs compiled to WASM.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Import the Stylus SDK along with alloy primitive types for use in our program.
use stylus_sdk::{
    alloy_primitives::{Address, FixedBytes, U256},
    alloy_sol_types::{eip712_domain, sol, SolStruct},
    block,
    call::RawCall,
    contract, evm,
    prelude::*,
};

/// Import the p256 elliptic curve library
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

// Define the entrypoint as a Solidity storage object

// Goal: create a single owner smart contract wallet that can use a p256 signature to approve transactions
sol_storage! {
    #[entrypoint]
    pub struct P256SCW {
        address singleton;
        uint256 nonce;
        // P256 public key of the owner
        bytes32 public_key;
    }
}

sol! {
    struct SCWTx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 nonce;
    }
}

impl SCWTx {
    pub fn new(to: Address, value: U256, data: Vec<u8>, operation: u8, nonce: U256) -> Self {
        SCWTx {
            to,
            value,
            data,
            operation,
            nonce,
        }
    }
}

// TODO move fn implementations into different blocks based on internal/external/view/pure/etc.
#[external]
impl P256SCW {
    pub fn constructor(&mut self, public_key: FixedBytes<32>) -> Result<(), Vec<u8>> {
        self.singleton.set(contract::address());
        self.public_key.set(public_key);
        Ok(())
    }

    pub fn nonce(&self) -> Result<U256, Vec<u8>> {
        Ok(self.nonce.get())
    }

    pub fn get_transaction_hash(
        &self,
        to: Address,
        value: U256,
        data: Vec<u8>,
        operation: u8,
        nonce: U256,
    ) -> Result<FixedBytes<32>, Vec<u8>> {
        let scw_tx = SCWTx::new(to, value, data, operation, nonce);
        let domain = eip712_domain! {
            name: "P256SCW",
            version: "0.1.0",
            chain_id: block::chainid(),
            verifying_contract: contract::address(),
        };
        Ok(scw_tx.eip712_signing_hash(&domain))
    }

    pub fn check_signature(&self, digest: Vec<u8>, signature: Vec<u8>) -> Result<bool, Vec<u8>> {
        // TODO check signature length to confirm it is valid
        // TODO ensure that public key is input in the right format to be parsed by p256

        let signature = Signature::from_slice(&signature).map_err(|_| "Invalid signature")?;
        let public_key = VerifyingKey::from_sec1_bytes(self.public_key.get().as_slice())
            .map_err(|_| "Invalid public key")?;
        Ok(public_key.verify(&digest, &signature).is_ok())
    }

    pub fn exec_transaction(
        &mut self,
        to: Address,
        value: U256,
        data: Vec<u8>,
        operation: u8,
        signature: Vec<u8>,
    ) -> Result<bool, Vec<u8>> {
        let nonce = self.nonce.get();
        let tx_hash = self.get_transaction_hash(to, value, data.clone(), operation, nonce)?;
        let signature_valid = self.check_signature(tx_hash.as_slice().to_vec(), signature)?;
        if !signature_valid {
            return Err("Invalid signature".into());
        }

        if operation == 0 {
            // Regular call
            // TODO check return value or determine if this will error if the call fails
            unsafe {
                let _ = RawCall::new_with_value(value)
                    .gas(evm::gas_left())
                    .skip_return_data()
                    .call(to, &data);
            }
        } else if operation == 1 {
            // Delegate call
            // Doesn't pass value amount
            // TODO check return value or determine if this will error if the call fails
            unsafe {
                let _ = RawCall::new_delegate()
                    .gas(evm::gas_left())
                    .skip_return_data()
                    .call(to, &data);
            }
        } else {
            // Error
            return Err("Invalid operation".into());
        }

        self.nonce.set(nonce + U256::from(1));
        Ok(true)
    }
}

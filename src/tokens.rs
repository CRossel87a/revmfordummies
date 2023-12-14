use ethers::prelude::*;
use ethers::abi::parse_abi;
use crate::forked_db::fork_db::ForkDB;
use crate::forked_db::{to_revm_address, to_revm_u256};
use revm::primitives::{TransactTo, ExecutionResult, Output, Bytes as aBytes, Log as rLog, B256};
use revm::EVM;
use anyhow::{bail, ensure};
use std::str::FromStr;
use anyhow::anyhow;

fn safe_hash_to_address(input: &B256) -> anyhow::Result<Address> {
    let bytes = input.get(12..32).ok_or_else(|| anyhow!("Failed to index byte array 12..32"))?;
    Ok(Address::from_slice(bytes))
}

pub fn verify_transfer(logs: Vec<rLog>,msgsender: Address, token: Address, recipient: Address, input_amount: U256) -> anyhow::Result<()> {

    let transfer_event = B256::from_str("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").unwrap();

    let log = logs.iter().find(|p| p.topics.first() == Some(&transfer_event)).ok_or_else( || 
        anyhow!("Missing transfer event")
    )?;

    let actual_token = Address::from_slice(&log.address.0.0);
    let actual_amount = U256::from_big_endian(&log.data.0);
    let sender = safe_hash_to_address(log.topics.get(1).ok_or_else( ||  anyhow!("Failed to get sender"))?)?;
    let actual_recipient = safe_hash_to_address(log.topics.get(2).ok_or_else( ||  anyhow!("Failed to get recipient"))?)?;

    ensure!(actual_amount == input_amount, "actual_amount != input_amount");
    ensure!(token == actual_token, "Wrong address on transfer event");
    ensure!(sender == msgsender,"topic sender != msgsender");
    ensure!(actual_recipient == recipient, "actual recipient != input recipient");

    Ok(())
}

pub async fn transfer(fork_db: &ForkDB, msgsender: Address, token: Address, recipient: Address, amount: U256) -> anyhow::Result<(aBytes,Vec<rLog>)> {

    let mut evm = EVM::new();
    evm.database(fork_db);

    let erc20 = BaseContract::from(
        parse_abi(&["function transfer(address recipient, uint amount) external returns (bool)"])?
    );

    let revert = BaseContract::from(
        parse_abi(&["function Error(string)"])?
    );

    let ethers_bytes: ethers::core::types::Bytes = erc20.encode("transfer", (recipient, amount))?;

    evm.env.tx.caller = to_revm_address(msgsender);
    evm.env.tx.transact_to = TransactTo::Call(token.0.into());
    evm.env.tx.data = revm::primitives::Bytes::from(ethers_bytes.0);
    evm.env.tx.gas_price = to_revm_u256(U256::from(3000000000u64));
    evm.env.tx.gas_limit = 1000000;
    evm.env.tx.value = to_revm_u256(U256::zero());

    let result = evm.transact_ref()?.result;
    
    match result {
        ExecutionResult::Success { output, logs, .. } => {
            match &output {
                Output::Call(output_bytes) => { 
                    Ok((output_bytes.clone(),logs))
                 }
                Output::Create(_, _) => { 
                    bail!("Unexpected scenario");
                }
            }
        }
        ExecutionResult::Revert { output, gas_used } => {

            let reason = revert.decode::<String,Bytes>("Error", ethers::types::Bytes(output.0))?;
            bail!(format!("Transfer failed with gas_used {} and reason: {}",gas_used,reason));
        }
        ExecutionResult::Halt { .. } => {
            bail!("Transfer failed");
        }
    }
}


pub async fn balance_of(fork_db: &ForkDB, owner_address: Address, token: Address) -> anyhow::Result<U256> {

    let mut evm = EVM::new();
    evm.database(fork_db);

    let erc20 = BaseContract::from(
        parse_abi(&["function balanceOf(address) external"])?
    );

    let ethers_bytes: ethers::core::types::Bytes = erc20.encode("balanceOf", owner_address)?;

    evm.env.tx.caller = to_revm_address(owner_address);
    evm.env.tx.transact_to = TransactTo::Call(token.0.into());
    evm.env.tx.data = revm::primitives::Bytes::from(ethers_bytes.0);
    evm.env.tx.gas_price = to_revm_u256(U256::from(3000000000u64));
    evm.env.tx.gas_limit = 1000000;
    evm.env.tx.value = to_revm_u256(U256::zero());

    let result = evm.transact_ref()?.result;

    match result {
        ExecutionResult::Success { output, .. } => {
            match &output {
                Output::Call(output_bytes) => { 
                    Ok(erc20.decode_output("balanceOf", output_bytes)?)
                 }
                Output::Create(_, _) => { 
                    bail!("Unexpected scenario");
                }
            }
        }
        ExecutionResult::Revert { .. } => {
            bail!("Failed to get balance");
        }
        ExecutionResult::Halt { .. } => {
            bail!("Failed to get balance");
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    use revm::db::{CacheDB, EmptyDB};
    use crate::forked_db::fork_factory::ForkFactory;
    use std::str::FromStr;
    use std::sync::Arc;


    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_balance_of() {
        let url: &str = "wss://rpc.pulsechain.com";
        let provider = Provider::<Ws>::connect(url).await.unwrap();
        let client = Arc::new(provider);
    
        let latest_block = client.get_block_number().await.unwrap();
    
        // convert to BlockId
        let latest_block_id = Some(
            BlockId::Number(BlockNumber::Number(latest_block))
        );
    
        // create an empty cache db
        let cache_db = CacheDB::new(EmptyDB::default());
    
        // setup backend
        let fork_factory = ForkFactory::new_sandbox_factory(client, cache_db, latest_block_id).await;
        let fork_db = fork_factory.new_sandbox_fork();
    

        let owner_address = Address::from_str("0x1b45b9148791d3a104184Cd5DFE5CE57193a3ee9").unwrap();
        let token_address = Address::from_str("0xefD766cCb38EaF1dfd701853BFCe31359239F305").unwrap();
    
        let balance = balance_of(&fork_db, owner_address, token_address).await;
        dbg!(balance);
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_transfer() {
        let url: &str = "wss://rpc.pulsechain.com";
        let provider = Provider::<Ws>::connect(url).await.unwrap();
        let client = Arc::new(provider);
    
        let latest_block = client.get_block_number().await.unwrap();
    
        // convert to BlockId
        let latest_block_id = Some(
            BlockId::Number(BlockNumber::Number(latest_block))
        );
    
        // create an empty cache db
        let cache_db = CacheDB::new(EmptyDB::default());
    
        // setup backend
        let fork_factory = ForkFactory::new_sandbox_factory(client, cache_db, latest_block_id).await;
        let fork_db = fork_factory.new_sandbox_fork();

        let msgsender = Address::from_str("0x3C1fd12D3E86b6A4E9EcF69b6F293f30a3A5fe7e").unwrap();
        //let token = Address::from_str("0x95B303987A60C71504D99Aa1b13B4DA07b0790ab").unwrap();
        let token = Address::from_str("0x4db9112fe1c3670a7adB5E206eF6Ce26707A2767").unwrap();
        
        let recipient = Address::from_str("0x0000000000000000000000000000000000001337").unwrap();
        let amount: U256 = U256::from(1337);

        match transfer(&fork_db, msgsender, token, recipient, amount).await {
            Ok((bytes, logs)) => {
                dbg!(bytes);
                dbg!(&logs);
        
                dbg!(verify_transfer(logs, msgsender, token, recipient, amount));
            },
            Err(err) => {
                dbg!(err);
            } 
        }
    }
}
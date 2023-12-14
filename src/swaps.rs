use ethers::prelude::*;
use ethers::abi::parse_abi;
use crate::forked_db::fork_db::ForkDB;
use crate::forked_db::{to_revm_address, to_revm_u256};
use revm::primitives::{TransactTo, ExecutionResult, Output, Bytes as aBytes, Log as rLog, B256, U256 as rU256};
use revm::EVM;
use anyhow::{bail, ensure};
use std::str::FromStr;
use anyhow::anyhow;

pub async fn check_transaction(fork_db: &ForkDB, tx: Transaction, block: Block<H256>) -> anyhow::Result<()> {

    let revert = BaseContract::from(
        parse_abi(&["function Error(string)"])?
    );


    let mut evm = EVM::new();
    evm.database(fork_db);

    // Set up block
    evm.env.block.number = rU256::from(block.number.unwrap_or_default().as_u64());
    evm.env.block.timestamp = to_revm_u256(block.timestamp);

    // Set up txn
    evm.env.tx.caller = to_revm_address(tx.recover_from()?);
    evm.env.tx.transact_to = TransactTo::Call(
        to_revm_address(
        tx.to.ok_or_else(|| anyhow!("Contract creation"))?
    ));
    evm.env.tx.data = revm::primitives::Bytes::from(tx.input.0);
    evm.env.tx.gas_limit = tx.gas.as_u64();
    evm.env.tx.gas_price = to_revm_u256(U256::from(3000000000u64));
    evm.env.tx.value = to_revm_u256(tx.value);

    match evm.transact_ref()?.result {
        ExecutionResult::Revert { gas_used, output } => {
            dbg!(&output);
            let reason = revert.decode::<String,Bytes>("Error", ethers::types::Bytes(output.0))?;
            println!("Revert: {} gas_used: {}",reason, gas_used);
        },
        ExecutionResult::Success { reason, gas_used, gas_refunded, logs, output } => {
            println!("Success: {:?} gas_used: {} gas_refunded: {}", reason,gas_used, gas_refunded);
            dbg!(logs);
            dbg!(output);
        },
        ExecutionResult::Halt { reason, gas_used } => {
            println!("Halt: {:?} gas_used {}",reason,gas_used);
        }
    }
    Ok(())
}




#[cfg(test)]
mod tests {

    use super::*;

    use revm::db::{CacheDB, EmptyDB};
    use crate::forked_db::fork_factory::ForkFactory;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Instant;


    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_swaps() {

        let url: &str = "wss://rpc.pulsechain.com";
        let provider = Provider::<Ws>::connect(url).await.unwrap();
        let client = Arc::new(provider);
    
        //let latest_block = client.get_block_number().await.unwrap();

        let tx_hash: H256 = H256::from_str("0x1697b07c34cd6e7e8dbaca11d020305c24c9da72e4af41d5df52025a16619dcc").unwrap();
        let tx = client.get_transaction(tx_hash).await.unwrap().unwrap();

        let prev_block = tx.block_number.unwrap() - 1;
        let prev_id: BlockId = prev_block.into();

        let block = client.get_block(prev_block).await.unwrap().unwrap();
    
        // create an empty cache db
        let cache_db = CacheDB::new(EmptyDB::default());
        // setup backend
        let fork_factory = ForkFactory::new_sandbox_factory(client, cache_db, Some(prev_id)).await;
        let fork_db = fork_factory.new_sandbox_fork();

        let t0 = Instant::now();
        let res = check_transaction(&fork_db, tx, block).await;
        let t1 = Instant::now();

        dbg!(t1-t0);

        dbg!(res);

    }
}
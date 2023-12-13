use ethers::prelude::*;
use ethers::abi::parse_abi;
use crate::forked_db::fork_db::ForkDB;
use crate::forked_db::{to_revm_address, to_revm_u256};
use revm::primitives::{TransactTo, ExecutionResult, Output};
use revm::EVM;
use anyhow::bail;


pub async fn balance_of(fork_db: &ForkDB, owner_address: Address, token: Address) -> anyhow::Result<U256> {

    let mut evm = EVM::new();
    evm.database(fork_db);

    let erc20 = BaseContract::from(
        parse_abi(&["function balanceOf(address) external returns (uint)"])?
    );

    let ethers_bytes: ethers::core::types::Bytes = erc20.encode("balanceOf", owner_address)?;

    // setup evm fields

    // convert ethers to primitive types
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
        let fork_factory = ForkFactory::new_sandbox_factory(client, cache_db, latest_block_id);
        let fork_db = fork_factory.new_sandbox_fork();
    

        let owner_address = Address::from_str("0x1b45b9148791d3a104184Cd5DFE5CE57193a3ee9").unwrap();
        let token_address = Address::from_str("0xefD766cCb38EaF1dfd701853BFCe31359239F305").unwrap();
    
        let balance = balance_of(&fork_db, owner_address, token_address).await.unwrap();
        dbg!(balance);
    }
}
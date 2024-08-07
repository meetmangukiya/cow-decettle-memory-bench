use alloy::{
    primitives::{address, Address},
    providers::{Provider, ProviderBuilder},
    rpc::types::Transaction,
    sol,
    sol_types::SolCall,
};
use eyre::Result;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::cell::Cell;

const GP_V2_SETTLEMENT: Address = address!("9008D19f58AAbD9eD0D60971565AA8510560ab41");

sol! {
#[sol(rpc)]
contract GPv2Settlement {
    #[derive(Debug)]
    struct InteractionData {
        address target;
        uint256 value;
        bytes callData;
    }

    struct OrderData {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        bytes32 kind;
        bool partiallyFillable;
        bytes32 sellTokenBalance;
        bytes32 buyTokenBalance;
    }

    #[derive(Debug)]
    struct TradeData {
        uint256 sellTokenIndex;
        uint256 buyTokenIndex;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        uint256 flags;
        uint256 executedAmount;
        bytes signature;
    }

    function settle(address[] calldata tokens, uint[] calldata clearingPrices, TradeData[] calldata trades, InteractionData[][3] calldata interactions) external;

    event Settlement(address indexed solver);
}
}

fn calldata_copy_cost(n_bytes: usize) -> usize {
    let n_words = if n_bytes % 32 == 0 {
        n_bytes / 32
    } else {
        (n_bytes / 32) + 1
    };
    3 + 3 * (n_words)
}

fn memory_expansion_cost(offset: usize) -> usize {
    let n_words = (offset + 31) / 32;
    (n_words.pow(2)) / 512 + (3 * n_words)
}

fn keccak256_cost(n_bytes: usize) -> usize {
    let n_words = (n_bytes + 31) / 32;
    30 + (6 * n_words)
}

fn compute_gas_fully_signed(args: &GPv2Settlement::settleCall, len: usize) -> usize {
    let n_tokens = args.tokens.len();
    let n_prices = args.clearingPrices.len();
    let n_trades = args.trades.len();

    let mut n_words = 0;
    n_words += 4; // offsets
                  // println!("after offset {}", n_words);

    n_words += 1; // tokens length
    n_words += n_tokens; // the n tokens

    n_words += 1; // prices length
    n_words += n_prices; // the n prices
    n_words += 1; // trades length
    n_words += n_trades; // the offsets

    for trade in &args.trades {
        // uint256 sellTokenIndex;
        // uint256 buyTokenIndex;
        // address receiver;
        // uint256 sellAmount;
        // uint256 buyAmount;
        // uint32 validTo;
        // bytes32 appData;
        // uint256 feeAmount;
        // uint256 flags;
        // uint256 executedAmount;
        // bytes signature;
        n_words += 11;
        n_words += 1; // the signature length
        let sig_len = trade.signature.len();
        let sig_words = (sig_len + 31) / 32;
        n_words += sig_words; // the signature words
    }
    // println!("after trades {}", n_words);

    n_words += 3; // the pre, intra, post interaction offsets

    for arr_interactions in &args.interactions {
        n_words += 1; // length of interactions;
        for interaction in arr_interactions {
            n_words += 1; // interaction offset
            n_words += 3; // target, value, offset
            n_words += 1; // interaction calldata length
            let interaction_data_len = interaction.callData.len();
            let interaction_words = (interaction_data_len + 31) / 32;
            n_words += interaction_words;
        }
        // println!("after interaction {}", n_words);
    }

    assert_eq!(n_words * 32, len - 8 - 4); // 8 bytes for the batch number, 4 for method selector
    n_words += 2; // solver, deadline
    let n_bytes = n_words * 32;

    calldata_copy_cost(n_bytes) + memory_expansion_cost(n_bytes) + keccak256_cost(n_bytes)
}

struct MemoryExpansionCosts {
    end_byte: Cell<usize>,
}

impl MemoryExpansionCosts {
    pub fn new() -> Self {
        Self {
            end_byte: Cell::new(0),
        }
    }

    pub fn expand_memory_words(&self, n_words: usize) {
        self.end_byte.set(self.end_byte.get() + (n_words * 32))
    }

    pub fn shrink_memory_words(&self, n_words: usize) {
        self.end_byte.set(self.end_byte.get() - (n_words * 32))
    }

    pub fn gas_costs(&self) -> usize {
        memory_expansion_cost(self.end_byte.get())
    }
}

fn compute_gas_partially_signed(args: &GPv2Settlement::settleCall, offsets: [usize; 3]) -> usize {
    let plain_copy = 4 + // offsets
        1 + // tokens length
        args.tokens.len() + // n tokens
        1 + // prices length
        args.clearingPrices.len() + // n prices
        1 + // trades length
        args.trades.len() + // n trade offsets
        (args.trades.len() * 12) + // 11 fields + 1 signature length
        args.trades.iter().map(|trade| {
            let len = trade.signature.len();
            (len + 31) / 32
        }).sum::<usize>(); // signature words

    let memory_costs = MemoryExpansionCosts::new();

    // copy everything uptil the trades
    let mut gas = 0;
    gas += calldata_copy_cost(plain_copy * 32);
    memory_costs.expand_memory_words(plain_copy);

    // the interaction offsets
    memory_costs.expand_memory_words(3);
    // length of the said interaction array
    memory_costs.expand_memory_words(3);
    // writing the offsets
    gas += 6 * 3; // 6 mstores

    let interaction_sizer = |interaction: &GPv2Settlement::InteractionData| {
        1 + // offset
        1 + // target
        1 + // value
        1 + // data offset
        1 + // data length
        (interaction.callData.len() + 31) / 32 // data words
    };
    // how many bytes to copy?
    let pre_interaction_words: usize = args.interactions[0][..offsets[0]]
        .iter()
        .map(interaction_sizer)
        .sum();
    let intra_interaction_words: usize = args.interactions[1][..offsets[1]]
        .iter()
        .map(interaction_sizer)
        .sum();
    let post_interaction_words: usize = args.interactions[2][..offsets[2]]
        .iter()
        .map(interaction_sizer)
        .sum();
    let total_partial_interaction_copy_words =
        pre_interaction_words + post_interaction_words + intra_interaction_words;
    // memory expansion and calldata copy
    memory_costs.expand_memory_words(total_partial_interaction_copy_words);
    gas += calldata_copy_cost(total_partial_interaction_copy_words * 32);
    // solver, deadline
    memory_costs.expand_memory_words(2);
    // hashing cost
    gas += keccak256_cost(memory_costs.end_byte.get());

    // copy over all the interactions again
    memory_costs.shrink_memory_words(total_partial_interaction_copy_words);
    let total_interaction_words: usize = args.interactions[0]
        .iter()
        .map(interaction_sizer)
        .sum::<usize>()
        + args.interactions[1]
            .iter()
            .map(interaction_sizer)
            .sum::<usize>()
        + args.interactions[2]
            .iter()
            .map(interaction_sizer)
            .sum::<usize>();
    memory_costs.expand_memory_words(total_interaction_words);
    gas += calldata_copy_cost(total_interaction_words * 32);

    gas += memory_costs.gas_costs();
    gas
}

#[allow(dead_code)]
fn pretty_print_tx_calldata(tx: &Transaction) {
    let data = &tx.input;
    println!("{} : {}", hex::encode(data.slice(0..4)), tx.hash);
    println!("--------");
    let n_words = ((data.len() - 4) + 31) / 32;
    let data_len = data.len();
    for i in 0..n_words {
        let start_byte = (i * 32) + 4;
        let end_byte = ((i + 1) * 32) + 4;
        let end_byte = if end_byte > data_len {
            data_len
        } else {
            end_byte
        };
        println!(
            "{idx:0>3} {number:0>3} {data} [{start_byte}..{end_byte}]",
            idx = i,
            number = format!("{:x}", i * 32),
            data = hex::encode(&data[start_byte..end_byte])
        );
    }
}

fn compute_gas(tx: &Transaction, rng: &mut StdRng) -> eyre::Result<(usize, usize, usize, usize)> {
    // pretty_print_tx_calldata(tx);
    let call_args = GPv2Settlement::settleCall::abi_decode(&tx.input, false)?;
    let n = [
        if call_args.interactions[0].is_empty() {
            0
        } else {
            rng.gen_range(0..call_args.interactions[0].len())
        },
        if call_args.interactions[1].is_empty() {
            0
        } else {
            rng.gen_range(0..call_args.interactions[1].len())
        },
        if call_args.interactions[2].is_empty() {
            0
        } else {
            rng.gen_range(0..call_args.interactions[2].len())
        },
    ];
    Ok((
        compute_gas_fully_signed(&call_args, tx.input.len()),
        compute_gas_partially_signed(&call_args, n),
        compute_gas_partially_signed(
            &call_args,
            [
                call_args.interactions[0].len(),
                call_args.interactions[1].len(),
                call_args.interactions[2].len(),
            ],
        ),
        compute_gas_partially_signed(&call_args, [0, 0, 0]),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up the HTTP transport which is consumed by the RPC client.
    let rpc_url = "https://eth.merkle.io".parse()?;

    // Create a provider with the HTTP transport using the `reqwest` crate.
    let provider = ProviderBuilder::new().on_http(rpc_url);
    // let latest_block = provider.get_block_number().await?;
    let latest_block = 20476152;

    let n_blocks = 100u64;
    let from_block = latest_block - n_blocks;

    let settlement = GPv2Settlement::new(GP_V2_SETTLEMENT, provider.clone());
    let filter = settlement
        .Settlement_filter()
        .filter
        .from_block(from_block)
        .to_block(latest_block);
    let logs = provider.get_logs(&filter).await?;
    let mut txs = Vec::with_capacity(logs.len());

    for log in logs {
        let tx_hash = log.transaction_hash.expect("tx hash not found");
        let tx = provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .expect("transaction not found");
        txs.push(tx);
    }

    let mut rng = StdRng::seed_from_u64(12345);
    let mut percents = Vec::with_capacity(txs.len());
    for tx in &txs {
        let (full_gas, partial_gas_rand, partial_gas_full, partial_gas_empty) =
            compute_gas(tx, &mut rng)?;
        let percent = |x: usize| (x as f64) / (full_gas as f64) * 100.;
        percents.push((
            percent(partial_gas_rand),
            percent(partial_gas_full),
            percent(partial_gas_empty),
        ));
        println!(
            "hash: {}, len: {}, fully_signed: {}, partially_signed: {} {} {}, percent: {}% {}% {}%",
            tx.hash,
            tx.input.len(),
            full_gas,
            partial_gas_rand,
            partial_gas_full,
            partial_gas_empty,
            percent(partial_gas_rand),
            percent(partial_gas_full),
            percent(partial_gas_empty)
        );
    }

    let avg = percents.iter().fold((0., 0., 0.), |acc, curr| {
        (acc.0 + curr.0, acc.1 + curr.1, acc.2 + curr.2)
    });
    let avg = (
        avg.0 / percents.len() as f64,
        avg.1 / percents.len() as f64,
        avg.2 / percents.len() as f64,
    );

    println!("average change: {:?}", avg);

    Ok(())
}

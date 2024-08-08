# cow-decettle-memory-bench

This project aims to provide some rough gas estimations for partially or fully signed settlement execution
via the [settlement wrapper contract](https://github.com/meetmangukiya/cow-decettle). See the 
[RFP](https://github.com/cowdao-grants/rfps/blob/main/RFP-01.md) for the same here.

## Definitions

### Signed settlement

We want to allow arbitrary solvers to be able to submit solutions to COW protocol provided the solution was
attested first by the autopilot. The solver can then submit their solution with the signature to prove
that the provided solution was valid and approved by the autopilot.

### Fully signed settlement

In fully signed settlement, the payload that will be signed will contain the full calldata of the subsequent
`GPv2Settlement.settle` call that will be made by the wrapper contract.

The params `solver`, `deadline` and `signature`(65 bytes) are appended to the end of calldata and are not made
part of the ABI, so that we can directly copy over the calldata and use the same offsets in memory to make the
external call to the `GPv2Settlement.settle` call.

```solidity
uint lastByteOfPostInteractions;
address solver = msg.sender;
uint deadline;
bytes32 r;
bytes32 s;
bytes32 v;

assembly {
    deadline := calldataload(lastByteOfPostInteractions)
    r := calldataload(add(lastByteOfPostInteractions, 0x20))
    s := calldataload(add(lastByteOfPostInteractions, 0x40))
    v := and(calldataload(add(lastByteOfPostInteractions, 0x41)), 0xff)
}
```

The payload that will be signed is as follows:

```solidity
bytes calldata data = abi.encodePacked(abi.encode(tokens, clearingPrices, trades, interactions), uint(uint160(solver)), deadline);
bytes32 digest = keccak256(data);
```

### Partially signed settlement.

Partially signed settlement is where only a subset of interactions are signed, instead of all of them.
The subset is determined by a `uint[3]` param that will contain the offset until which the interactions should
be signed.

The params `solver`, `deadline` and `signature`(65 bytes) are appended to the end of calldata and are not made
part of the ABI, so that we can directly copy over the calldata and use the same offsets in memory to make the
external call to the `GPv2Settlement.settle` call.

```solidity
uint lastByteOfPostInteractions;
address solver = msg.sender;
uint deadline;
bytes32 r;
bytes32 s;
bytes32 v;

assembly {
    deadline := calldataload(lastByteOfPostInteractions)
    r := calldataload(add(lastByteOfPostInteractions, 0x20))
    s := calldataload(add(lastByteOfPostInteractions, 0x40))
    v := and(calldataload(add(lastByteOfPostInteractions, 0x41)), 0xff)
}
```

The payload that will be signed for partially signed is as follows:

```solidity
uint[3] memory offsets = [2, 1, 4];
GPv2Interaction.Data[] memory preInteractionsSubset;
GPv2Interaction.Data[] memory intraInteractionsSubset;
GPv2Interaction.Data[] memory postInteractionsSubset;
GPv2Interaction.Data[] memory preInteractions = interactions[0];
GPv2Interaction.Data[] memory intraInteractions = interactions[1];
GPv2Interaction.Data[] memory postInteractions = interactions[2];
uint[3] memory ogLengths = [preInteractions.length, intraInteractions.length, postInteractions.length];

// directly override length in memory to have the same effect
assembly {
    preInteractionsSubset := preInteractions
    mstore(preInteractionsSubset, mload(offsets))
    intraInteractionsSubset := intraInteractions
    mstore(intraInteractionsSubset, mload(add(offsets, 0x20)))
    postInteractionSubsets := postInteractions
    mstore(postInteractionsSubset, mload(add(offsets, 0x40)))
}

GPv2Interaction.Data[][3] memory interactionsSubset = [preInteractionsSubset, intraInteractionsSubset, postInteractionsSubset];
bytes calldata data = abi.encodePacked(abi.encode(tokens, clearingPrices, trades, interactionsSubset), uint(uint160(solver)), deadline);
bytes32 digest = keccak256(data);
```

## Implementations

### Fully signed calldata

Creating the payload for signing this in memory is simple

```solidity
uint lastByteOfPostInteractions
bytes32 digest;

assembly {
    let freeMemPtr := mload(0x40)
    calldatacopy(freeMemPtr, 0x04, sub(lastByteOfPostInteractions, 0x04))
    mstore(add(freeMemPtr, 0x20), caller())
    mstore(add(freeMemPtr, 0x40), deadline)
    digest := keccak256(0x00, add(freeMemPtr, 0x40))
}
```

### Partially signed calldata

Here, we can copy over all the data before interactions from calldata to memory just fine without
requiring any changes. After that there will be the interactions offset, we cannot copy this over
because the offset will be different since its only a subset of interactions.

Not exact assembly but pseudo assembly would look like this for inplace modifications for getting
ABI encoded data for the subset of interactions.

```solidity
uint lastByteOfTrades;
// this is what points to the first interaction offset,
// the word after that will point to intraInteractions offset,
// and the word after postInteractions
uint interactionsPtrByte;
uint preInteractionSubsetOffset; // offsets[0]

assembly {
    let freeMemPtr := mload(0x40)
    calldatacopy(freeMemPtr, 0x04, sub(lastByteOfTrades, 0x04))
    // skip 4 words for the 3 offsets

    // store the preinteractions subset length
    mstore(add(interactionsPtrByte, 0x60), preInteractionSubsetOffset)
    // copy the interaction offsets
    calldatacopy(add(add(freeMemPtr, sub(lastByteOfTrades, 0x04)), 0x04), add(interactionsPtrByte, 0x80), mul(preInteractionSubsetOffset 0x20))
    // copy over the subset of interactions
    calldatacopy(..., ..., ...)
    // store the intraInteractions subset length
    ...
    // copy the intraInteraction offsets
    ...
    // store over the subset of intra interactions
    ...
    // store the postInteractions subset length
    ...
    // copy the postInteraction offsets
    ...
    // store over the subset of post interactions
    ...
    // now that all memory is set, we can store the modifed interactions offsets at interactionsPtrByte, interactionsPtrByte + 32, interactionsPtrByte + 32
    ...

    // append solver
    // append deadline
    // hash the data to get digest

    // overwrite from the `interactionPtrByte` with the original calldata to get the calldata for the external settle call
}
```

## Gas estimations

Now that we know what we are looking to implement, we try to write the gas cost estimation math
in this program defined at [`main.rs`](./src/main.rs). We are mainly concerned about the
calldatacopy costs, memory expansion costs, and any mstores we can recognize, and keccak256 cost.

`keccak256` is 2x as expensive as `calldatacopy` so as it turns out in the [results](./output)
in random case of partially signed calldata, partially signed is cheaper because of this difference
in costs. Partially signed uses `calldatacopy` for `[1..2]x` the calldata size but keccak is `< 1x` of calldata.
While fully signed uses `calldatacopy` only `1x` and keccak256 also only `1x` of calldata. So, the difference in
gas costs of keccak256 / byte can make the partially signed one cheaper.

The memory expansion costs between the two is same because of the technique we employ for in-place changing of
memory to get ABI compliant encoding of subset of interactions.

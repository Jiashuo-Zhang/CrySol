// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

import { SafeTransferLib } from "../lib/SafeTransferLib.sol";
import { IWETH9 } from "./interfaces/IWETH9.sol";
import { TSAggregator } from "./TSAggregator.sol";
import { IThorchainRouter } from "./interfaces/IThorchainRouter.sol";
import { IUniswapRouterV3 } from "./interfaces/IUniswapRouterV3.sol";

contract TSAggregatorUniswapV3 is TSAggregator {
    using SafeTransferLib for address;

    IWETH9 public weth;
    uint24 public poolFee;
    IUniswapRouterV3 public swapRouter;

    constructor(
        address _ttp, address _weth, address _swapRouter, uint24 _poolFee
    ) TSAggregator(_ttp) {
        weth = IWETH9(_weth);
        poolFee = _poolFee;
        swapRouter = IUniswapRouterV3(_swapRouter);
    }

    function swapIn(
        address tcRouter,
        address tcVault,
        string calldata tcMemo,
        address token,
        uint amount,
        uint amountOutMin,
        uint deadline
    ) public nonReentrant {
        tokenTransferProxy.transferTokens(token, msg.sender, address(this), amount);
        token.safeApprove(address(swapRouter), 0); // USDT quirk
        token.safeApprove(address(swapRouter), amount);

        uint amountOut = swapRouter.exactInputSingle(IUniswapRouterV3.ExactInputSingleParams({
            tokenIn: token,
            tokenOut: address(weth),
            fee: poolFee,
            recipient: address(this),
            deadline: deadline,
            amountIn: amount,
            amountOutMinimum: amountOutMin,
            sqrtPriceLimitX96: 0
        }));
        weth.withdraw(amountOut);

        amountOut = skimFee(amountOut);
        IThorchainRouter(tcRouter).depositWithExpiry{value: amountOut}(
            payable(tcVault),
            address(0), // ETH
            amountOut,
            tcMemo,
            deadline
        );
    }

    function swapOut(address token, address to, uint256 amountOutMin) public payable nonReentrant {
        uint256 amount = skimFee(msg.value);
        weth.deposit{value: amount}();
        address(weth).safeApprove(address(swapRouter), amount);
        swapRouter.exactInputSingle(IUniswapRouterV3.ExactInputSingleParams({
            tokenIn: address(weth),
            tokenOut: token,
            fee: poolFee,
            recipient: to,
            deadline: type(uint).max,
            amountIn: amount,
            amountOutMinimum: amountOutMin,
            sqrtPriceLimitX96: 0
        }));
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Safe ETH and ERC20 transfer library that gracefully handles missing return values.
/// @author Solmate (https://github.com/Rari-Capital/solmate/blob/main/src/utils/SafeTransferLib.sol)
/// @author Modified from Gnosis (https://github.com/gnosis/gp-v2-contracts/blob/main/src/contracts/libraries/GPv2SafeERC20.sol)
/// @dev Use with caution! Some functions in this library knowingly create dirty bits at the destination of the free memory pointer.
library SafeTransferLib {
    /*///////////////////////////////////////////////////////////////
                            ETH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function safeTransferETH(address to, uint256 amount) internal {
        bool callStatus;

        assembly {
            // Transfer the ETH and store if it succeeded or not.
            callStatus := call(gas(), to, amount, 0, 0, 0, 0)
        }

        require(callStatus, "ETH_TRANSFER_FAILED");
    }

    /*///////////////////////////////////////////////////////////////
                           ERC20 OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal {
        bool callStatus;

        assembly {
            // Get a pointer to some free memory.
            let freeMemoryPointer := mload(0x40)

            // Write the abi-encoded calldata to memory piece by piece:
            mstore(freeMemoryPointer, 0x23b872dd00000000000000000000000000000000000000000000000000000000) // Begin with the function selector.
            mstore(add(freeMemoryPointer, 4), and(from, 0xffffffffffffffffffffffffffffffffffffffff)) // Mask and append the "from" argument.
            mstore(add(freeMemoryPointer, 36), and(to, 0xffffffffffffffffffffffffffffffffffffffff)) // Mask and append the "to" argument.
            mstore(add(freeMemoryPointer, 68), amount) // Finally append the "amount" argument. No mask as it's a full 32 byte value.

            // Call the token and store if it succeeded or not.
            // We use 100 because the calldata length is 4 + 32 * 3.
            callStatus := call(gas(), token, 0, freeMemoryPointer, 100, 0, 0)
        }

        require(didLastOptionalReturnCallSucceed(callStatus), "TRANSFER_FROM_FAILED");
    }

    function safeTransfer(
        address token,
        address to,
        uint256 amount
    ) internal {
        bool callStatus;

        assembly {
            // Get a pointer to some free memory.
            let freeMemoryPointer := mload(0x40)

            // Write the abi-encoded calldata to memory piece by piece:
            mstore(freeMemoryPointer, 0xa9059cbb00000000000000000000000000000000000000000000000000000000) // Begin with the function selector.
            mstore(add(freeMemoryPointer, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff)) // Mask and append the "to" argument.
            mstore(add(freeMemoryPointer, 36), amount) // Finally append the "amount" argument. No mask as it's a full 32 byte value.

            // Call the token and store if it succeeded or not.
            // We use 68 because the calldata length is 4 + 32 * 2.
            callStatus := call(gas(), token, 0, freeMemoryPointer, 68, 0, 0)
        }

        require(didLastOptionalReturnCallSucceed(callStatus), "TRANSFER_FAILED");
    }

    function safeApprove(
        address token,
        address to,
        uint256 amount
    ) internal {
        bool callStatus;

        assembly {
            // Get a pointer to some free memory.
            let freeMemoryPointer := mload(0x40)

            // Write the abi-encoded calldata to memory piece by piece:
            mstore(freeMemoryPointer, 0x095ea7b300000000000000000000000000000000000000000000000000000000) // Begin with the function selector.
            mstore(add(freeMemoryPointer, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff)) // Mask and append the "to" argument.
            mstore(add(freeMemoryPointer, 36), amount) // Finally append the "amount" argument. No mask as it's a full 32 byte value.

            // Call the token and store if it succeeded or not.
            // We use 68 because the calldata length is 4 + 32 * 2.
            callStatus := call(gas(), token, 0, freeMemoryPointer, 68, 0, 0)
        }

        require(didLastOptionalReturnCallSucceed(callStatus), "APPROVE_FAILED");
    }

    /*///////////////////////////////////////////////////////////////
                         INTERNAL HELPER LOGIC
    //////////////////////////////////////////////////////////////*/

    function didLastOptionalReturnCallSucceed(bool callStatus) private pure returns (bool success) {
        assembly {
            // Get how many bytes the call returned.
            let returnDataSize := returndatasize()

            // If the call reverted:
            if iszero(callStatus) {
                // Copy the revert message into memory.
                returndatacopy(0, 0, returnDataSize)

                // Revert with the same message.
                revert(0, returnDataSize)
            }

            switch returnDataSize
            case 32 {
                // Copy the return data into memory.
                returndatacopy(0, 0, returnDataSize)

                // Set success to whether it returned true.
                success := iszero(iszero(mload(0)))
            }
            case 0 {
                // There was no return data.
                success := 1
            }
            default {
                // It returned some malformed input.
                success := 0
            }
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

interface IWETH9 {
    function deposit() external payable;
    function withdraw(uint256) external;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

import { SafeTransferLib } from "../lib/SafeTransferLib.sol";
import { ReentrancyGuard } from "../lib/ReentrancyGuard.sol";
import { Owners } from "./Owners.sol";
import { TSAggregatorTokenTransferProxy } from './TSAggregatorTokenTransferProxy.sol';

abstract contract TSAggregator is Owners, ReentrancyGuard {
    using SafeTransferLib for address;

    event FeeSet(uint256 fee, address feeRecipient);

    uint256 public fee;
    address public feeRecipient;
    TSAggregatorTokenTransferProxy public tokenTransferProxy;

    constructor(address _tokenTransferProxy) {
        _setOwner(msg.sender, true);
        tokenTransferProxy = TSAggregatorTokenTransferProxy(_tokenTransferProxy);
    }

    // Needed for the swap router to be able to send back ETH
    receive() external payable {}

    function setFee(uint256 _fee, address _feeRecipient) external isOwner {
        require(_fee <= 1000, "fee can not be more than 10%");
        fee = _fee;
        feeRecipient = _feeRecipient;
        emit FeeSet(_fee, _feeRecipient);
    }

    function skimFee(uint256 amount) internal returns (uint256) {
        if (fee != 0 && feeRecipient != address(0)) {
            uint256 feeAmount = (amount * fee) / 10000;
            feeRecipient.safeTransferETH(feeAmount);
            amount -= feeAmount;
        }
        return amount;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

interface IThorchainRouter {
    function depositWithExpiry(
        address payable vault,
        address asset,
        uint amount,
        string memory memo,
        uint expiration
    ) external payable;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

interface IUniswapRouterV3 {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    struct ExactInputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
    }

    function exactInputSingle(
        ExactInputSingleParams calldata params
    ) external returns (uint256 amountOut);

    function exactInput(
        ExactInputParams calldata params
    ) external returns (uint256 amountOut);
}

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Gas optimized reentrancy protection for smart contracts.
/// @author Solmate (https://github.com/Rari-Capital/solmate/blob/main/src/utils/ReentrancyGuard.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/security/ReentrancyGuard.sol)
abstract contract ReentrancyGuard {
    uint256 private locked = 1;

    modifier nonReentrant() {
        require(locked == 1, "REENTRANCY");

        locked = 2;

        _;

        locked = 1;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

abstract contract Owners {
    event OwnerSet(address indexed owner, bool active);

    mapping(address => bool) public owners;

    modifier isOwner() {
        require(owners[msg.sender], "Unauthorized");
        _;
    }

    function _setOwner(address owner, bool active) internal virtual {
      owners[owner] = active;
      emit OwnerSet(owner, active);
    }

    function setOwner(address owner, bool active) external virtual isOwner {
      _setOwner(owner, active);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

import { SafeTransferLib } from "../lib/SafeTransferLib.sol";
import { Owners } from "./Owners.sol";

contract TSAggregatorTokenTransferProxy is Owners {
    using SafeTransferLib for address;

    constructor() {
        _setOwner(msg.sender, true);
    }

    function transferTokens(address token, address from, address to, uint256 amount) external isOwner {
        require(from == tx.origin || _isContract(from), "Invalid from address");
        token.safeTransferFrom(from, to, amount);
    }

    function _isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.
        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}
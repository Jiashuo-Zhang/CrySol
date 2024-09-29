/**
 *Submitted for verification at Etherscan.io on 2022-03-23
*/

// SPDX-License-Identifier: MIT

//                                .+z}'
//                              ,fXEXk}
//                ^!~'  ,<nwU6EzNaPDRRE`
//               ~kkXw\SRR%gW888NNWDqbs
//               ,wRh7DDdRR%%DqKKdRgWy'
//                *X|qPXqDDRRR%%%%%%%%L`
//                 'YKDDDDDDDDDdUA6KRRd`
//                  [email protected]@[email protected]~
//                  [email protected]@RWqDK;
//                  ~bUQQBgAd}DDDDqxts}'
//                   zofuAddd~;jKDdwzii
//                   .|7JXqK}}=ozbdwoP;  `'.`
//                    '*7tXUUUqqKbbddL  !*?L>!+!`
//                      ;zSwPkXUAqAt~`':++!^=?7mL`
//                        `,;^cTc7c7._,^+;;=<|<|vL`
//                           `<ykz>|;~';~~===;!<*i^
//                        `;Liubyaj!~~_,,~!;~+=+!*\'
//                      ,<?JbzPRkjJz=',,_:',_~~!+~`
//                    `+hbbXRUa5sJzT7*~,,,,~~~,`
//                    ~zKKKEhNJzzz7vi\7Jci+^|7*
//          `         :oqqXjwZc77vTccjwqbALwEamA.
//         '!;=!^^'   ,tXjvTTT7vv\7{wqbDRofjwEwhQ!
//        '!!^;^^^*'  'i\\\\zyjzt}kAqKD%%iEmahEmhQI
//        `:;;!^+!;:',,LiiTzI\zz}kAAqbRgXfywwSkwmXQq`
//          `'~~~;!!!^~||L|77y;~~~;^[email protected],
//             `.,~~~~,!~'~xjj*```,,,',:[email protected],
//                   ```.`,<LL~,~;^+^;_,,[email protected],
//                     '~;+<<[email protected]@B`
//                   `!?*?i\Lzyk6kP6qqbDDy{[email protected]@K
//                 `,i\\||\[email protected]@@c
//             ';*|Lv\\\\\i\Jow<[email protected]@@~
//           ,*\\>Jxc\\\\\\\iL?;[email protected]@@K`
//  ,'     ~Lc*:`Lj\iLLii\\\\\[email protected]@@~`
//  iA6m5S6y+'  ~uiiL||Li\7Yz{mZ+\[email protected]@@j`
//   ';+<+;`    =\iL|||LzyjvxwwE*[email protected]@@N``
//              '|iL|||L7T\<^[email protected]@@@``
//               `;*?|L*r;;+|<KKu^[email protected]@@@`
//                 `:~:_~~~;rL;  `*+=++=|[email protected]@@Q
//                  ^o!~~~~~~!|!` :~~^+++=|[email protected]@@@h
//                `5QWR?.,~~~~;=; `~~;++++?,[email protected]@@@;
//               ^qyL_    `,~~~!^  _~;r===|.  .,~;^[email protected]@@@d
//              '`          `~~;*` .~;^===|'        ,[email protected]@@Q'
//                           '~!<`  ~~!+==|,       '[email protected]@@Q~
//                            .'`   .~;+==<~      ,[email protected]@@b~
//                                   ~~^++=^`    *[email protected]_
//                                   `~~;^+|.   z6f!`
//                                    _~~r+7`
//                                    '~~!+v
//                                    `_~;^|`
//                                     `',,.



//      _______  _______  ___   _______  _______  __   __  _______  _______  _     _
//     |       ||   _   ||   | |       ||   _   ||  |_|  ||       ||       || | _ | |
//     |  _____||  |_|  ||   | |_     _||  |_|  ||       ||    ___||   _   || || || |
//     | |_____ |       ||   |   |   |  |       ||       ||   |___ |  | |  ||       |
//     |_____  ||       ||   |   |   |  |       ||       ||    ___||  |_|  ||       |
//      _____| ||   _   ||   |   |   |  |   _   || ||_|| ||   |___ |       ||   _   |
//     |_______||__| |__||___|   |___|  |__| |__||_|   |_||_______||_______||__| |__|


//   ...::: tg:  https://t.me/saitameowportal
//    ...:: twt: https://twitter.com/SaitameowToken
//     ...: web: https://saitameow.com


pragma solidity 0.8.11;

abstract contract Context {
    function _msgSender() internal view virtual returns (address payable) {
        return payable(msg.sender);
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

interface IERC20 {
    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount)
        external
        returns (bool);

    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

library Address {
    function isContract(address account) internal view returns (bool) {
        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            codehash := extcodehash(account)
        }
        return (codehash != accountHash && codehash != 0x0);
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        require(
            address(this).balance >= amount,
            "Address: insufficient balance"
        );

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{value: amount}("");
        require(
            success,
            "Address: unable to send value, recipient may have reverted"
        );
    }

    function functionCall(address target, bytes memory data)
        internal
        returns (bytes memory)
    {
        return functionCall(target, data, "Address: low-level call failed");
    }

    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return _functionCallWithValue(target, data, 0, errorMessage);
    }

    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return
            functionCallWithValue(
                target,
                data,
                value,
                "Address: low-level call with value failed"
            );
    }

    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(
            address(this).balance >= value,
            "Address: insufficient balance for call"
        );
        return _functionCallWithValue(target, data, value, errorMessage);
    }

    function _functionCallWithValue(
        address target,
        bytes memory data,
        uint256 weiValue,
        string memory errorMessage
    ) private returns (bytes memory) {
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: weiValue}(
            data
        );
        if (success) {
            return returndata;
        } else {
            if (returndata.length > 0) {
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}

contract Ownable is Context {
    address private _owner;
    address private _previousOwner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    constructor() {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() external virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) external virtual onlyOwner {
        require(
            newOwner != address(0),
            "Ownable: new owner is the zero address"
        );
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    function getTime() public view returns (uint256) {
        return block.timestamp;
    }
}


interface IDexRouter {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);

    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);

    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;

    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;

    function addLiquidityETH(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    )
        external
        payable
        returns (
            uint256 amountToken,
            uint256 amountETH,
            uint256 liquidity
        );

}

interface IDexFactory {
    function createPair(address tokenA, address tokenB)
        external
        returns (address pair);
}

contract SaitameowToken is Context, IERC20, Ownable {
    using SafeMath for uint256;
    using Address for address;

    address payable public operationsAddress;
    address payable public devAddress;

    mapping(address => uint256) private _rOwned;
    mapping(address => uint256) private _tOwned;
    mapping(address => mapping(address => uint256)) private _allowances;

    // Anti-bot and anti-whale mappings and variables
    mapping(address => uint256) private _holderLastTransferTimestamp; // to hold last Transfers temporarily during launch
    bool public transferDelayEnabled = false;
    bool public limitsInEffect = true;

    mapping(address => bool) private _isExcludedFromFee;
    mapping(address => bool) private _isExcluded;
    address[] private _excluded;

    uint256 private constant MAX = ~uint256(0);
    uint256 private constant _tTotal = 1 * 1e12 * 1e18;
    uint256 private _rTotal = (MAX - (MAX % _tTotal));
    uint256 private _tFeeTotal;

    string private constant _name = "Saitameow";
    string private constant _symbol = "SAITAMEOW";
    uint8 private constant _decimals = 18;

    // these values are pretty much arbitrary since they get overwritten for every txn, but the placeholders make it easier to work with current contract.
    uint256 private _taxFee;
    uint256 private _previousTaxFee = _taxFee;

    uint256 private _operationsFee;

    uint256 private _liquidityFee;
    uint256 private _previousLiquidityFee = _liquidityFee;

    uint256 private constant BUY = 1;
    uint256 private constant SELL = 2;
    uint256 private constant TRANSFER = 3;
    uint256 private buyOrSellSwitch;

    uint256 public _buyTaxFee = 200;
    uint256 public _buyLiquidityFee = 200;
    uint256 public _buyOperationsFee = 800;

    uint256 public _sellTaxFee = 200;
    uint256 public _sellLiquidityFee = 400;
    uint256 public _sellOperationsFee = 1200;

    mapping (address => bool) public privateSaleWallets;
    mapping (address => uint256) public nextPrivateWalletSellDate;
    uint256 public maxPrivSaleSell = 1.1 ether;

    uint256 public launchBlock = 0; // 0 means trading is not active
    uint256 private earlyBlocks;
    mapping (address => bool) public earlyBird;
    uint256 public birdsCaught;

    uint256 public _liquidityTokensToSwap;
    uint256 public _operationsTokensToSwap;

    uint256 public maxTransactionAmount;
    uint256 public maxWalletLimit;
    mapping (address => bool) public _isExcludedMaxTransactionAmount;
    mapping (address => bool) public _isExcludedFromWalletLimit;

    // store addresses that a automatic market maker pairs. Any transfer *to* these addresses
    // could be subject to a maximum transfer amount
    mapping (address => bool) public automatedMarketMakerPairs;

    uint256 private minimumTokensBeforeSwap;

    IDexRouter public dexRouter;
    address public lpPair;

    bool inSwapAndLiquify;
    bool public swapAndLiquifyEnabled = false;
    bool public tradingActive = false;

    event SwapAndLiquifyEnabledUpdated(bool enabled);
    event SwapAndLiquify(
        uint256 tokensSwapped,
        uint256 ethReceived,
        uint256 tokensIntoLiquidity
    );

    event SwapETHForTokens(uint256 amountIn, address[] path);

    event SwapTokensForETH(uint256 amountIn, address[] path);

    event SetAutomatedMarketMakerPair(address pair, bool value);

    event ExcludeFromReward(address excludedAddress);

    event IncludeInReward(address includedAddress);

    event ExcludeFromFee(address excludedAddress);

    event IncludeInFee(address includedAddress);

    event SetBuyFee(uint256 operationsFee, uint256 liquidityFee, uint256 reflectFee);

    event SetSellFee(uint256 operationsFee, uint256 liquidityFee, uint256 reflectFee);

    event TransferForeignToken(address token, uint256 amount);

    event UpdatedOperationsAddress(address operations);

    event OwnerForcedSwapBack(uint256 timestamp);

    event CaughtEarlyBird(address bird);

    event Meow();

    event LimitsRemoved();

    event TransferDelayDisabled();

    event UpdatedPrivateMaxSell(uint256 amount);


    modifier lockTheSwap() {
        inSwapAndLiquify = true;
        _;
        inSwapAndLiquify = false;
    }



    constructor() payable {
        _rOwned[address(this)] = _rTotal/100*25;
        _rOwned[0xaF9DdeA7C3CDE29Ac792CA261C5433C418300A39] = _rTotal/100*10;
        _rOwned[address(0xdead)] = _rTotal/100*50;
        _rOwned[msg.sender] = _rTotal/100*15;

        maxTransactionAmount = _tTotal * 1 / 10000;
        minimumTokensBeforeSwap = _tTotal * 50 / 100000;

        operationsAddress = payable(0x61e71f4ADAae18ebC294bfc4da47f3dd8335a343); // DEV + MARKETING OPERATIONS ADDRESS

        _isExcludedFromFee[owner()] = true;
        _isExcludedFromFee[address(this)] = true;
        _isExcludedFromFee[0xaF9DdeA7C3CDE29Ac792CA261C5433C418300A39] = true;
        _isExcludedFromFee[0x61e71f4ADAae18ebC294bfc4da47f3dd8335a343] = true;

        excludeFromMaxTransaction(owner(), true);
        excludeFromMaxTransaction(address(this), true);
        excludeFromMaxTransaction(address(0xdead), true);
        excludeFromMaxTransaction(0xaF9DdeA7C3CDE29Ac792CA261C5433C418300A39, true);
        excludeFromMaxTransaction(0x61e71f4ADAae18ebC294bfc4da47f3dd8335a343, true);

        excludeFromMaxWallet(owner(), true);
        excludeFromMaxWallet(address(this), true);
        excludeFromMaxWallet(address(0xdead), true);
        excludeFromMaxWallet(0xaF9DdeA7C3CDE29Ac792CA261C5433C418300A39, true);
        excludeFromMaxWallet(0x61e71f4ADAae18ebC294bfc4da47f3dd8335a343, true);

        excludeFromReward(msg.sender);

        emit Transfer(address(0), address(this), _tTotal/100*25);
        emit Transfer(address(0), address(0xaF9DdeA7C3CDE29Ac792CA261C5433C418300A39), _tTotal/100*10);
        emit Transfer(address(0), address(0xdead), _tTotal/1000*50);
        emit Transfer(address(0), address(msg.sender), _tTotal/100*15);
    }

    function name() external pure returns (string memory) {
        return _name;
    }

    function symbol() external pure returns (string memory) {
        return _symbol;
    }

    function decimals() external pure returns (uint8) {
        return _decimals;
    }

    function totalSupply() external pure override returns (uint256) {
        return _tTotal;
    }

    function balanceOf(address account) public view override returns (uint256) {
        if (_isExcluded[account]) return _tOwned[account];
        return tokenFromReflection(_rOwned[account]);
    }

    function transfer(address recipient, uint256 amount)
        external
        override
        returns (bool)
    {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender)
        external
        view
        override
        returns (uint256)
    {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount)
        public
        override
        returns (bool)
    {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) public returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        unchecked {
            _approve(sender, _msgSender(), currentAllowance - amount);
        }

        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender] + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        uint256 currentAllowance = _allowances[_msgSender()][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked {
            _approve(_msgSender(), spender, currentAllowance - subtractedValue);
        }

        return true;
    }

    function isExcludedFromReward(address account)
        external
        view
        returns (bool)
    {
        return _isExcluded[account];
    }

    function totalFees() external view returns (uint256) {
        return _tFeeTotal;
    }

    // remove limits after token is stable - 30-60 minutes
    function removeLimits() external onlyOwner {
        limitsInEffect = false;
        transferDelayEnabled = false;
        emit LimitsRemoved();
    }

    // disable Transfer delay
    function disableTransferDelay() external onlyOwner {
        transferDelayEnabled = false;
        emit TransferDelayDisabled();
    }

    function _caughtEarlyBird(address wallet, bool value) internal {
        earlyBird[wallet] = value;
    }

    function addEarlyBird(address wallet) external onlyOwner() {
        require(!earlyBird[wallet], "The bird is the word.");
        require(wallet != lpPair, "This is the Uniswap pair silly");
        _caughtEarlyBird(wallet, true);
    }

    function reviveEarlyBird(address wallet) external onlyOwner {
        require(earlyBird[wallet], "Early bird caught the worm!");
        _caughtEarlyBird(wallet, false);
    }

    function excludeFromMaxTransaction(address updAds, bool isEx) public onlyOwner {
        _isExcludedMaxTransactionAmount[updAds] = isEx;
    }

    function excludeFromMaxWallet(address updAds, bool isEx) public onlyOwner {
        _isExcludedFromWalletLimit[updAds] = isEx;
    }

    function minimumTokensBeforeSwapAmount() external view returns (uint256) {
        return minimumTokensBeforeSwap;
    }

    function setPrivateSaleMaxSell(uint256 amount) external onlyOwner{
        require(amount >= 25 && amount <= 500, "Must set between 0.25 and 50 ETH");
        maxPrivSaleSell = amount * 1e16;
        emit UpdatedPrivateMaxSell(amount);
    }

     // change the minimum amount of tokens to sell from fees
    function updateMinimumTokensBeforeSwap(uint256 newAmount) external onlyOwner{
  	    require(newAmount >= _tTotal * 1 / 100000, "Swap amount cannot be lower than 0.001% total supply.");
  	    require(newAmount <= _tTotal * 5 / 1000, "Swap amount cannot be higher than 0.5% total supply.");
  	    minimumTokensBeforeSwap = newAmount;
  	}

    function updateMaxTransaction(uint256 newNum) external onlyOwner {
        require(newNum >= (_tTotal * 2 / 1000)/1e18, "Cannot set maxTransactionAmount lower than 0.2%");
        maxTransactionAmount = newNum * (1e18);
    }

    function updateMaxWallet(uint256 newNum) external onlyOwner {
        require(newNum >= (_tTotal * 1 / 1000)/1e18, "Cannot set maxWalletLimit lower than 1%");
        maxWalletLimit = newNum * (1e18);
    }

    function setAutomatedMarketMakerPair(address pair, bool value) public onlyOwner {
        require(pair != lpPair, "The pair cannot be removed from automatedMarketMakerPairs");
        _setAutomatedMarketMakerPair(pair, value);
    }

    function _setAutomatedMarketMakerPair(address pair, bool value) private {
        automatedMarketMakerPairs[pair] = value;
        _isExcludedMaxTransactionAmount[pair] = value;
        _isExcludedFromWalletLimit[pair] = value;
        if(value){excludeFromReward(pair);}
        if(!value){includeInReward(pair);}
    }

    function reflectionFromToken(uint256 tAmount, bool deductTransferFee)
        external
        view
        returns (uint256)
    {
        require(tAmount <= _tTotal, "Amount must be less than supply");
        if (!deductTransferFee) {
            (uint256 rAmount, , , , , ) = _getValues(tAmount);
            return rAmount;
        } else {
            (, uint256 rTransferAmount, , , , ) = _getValues(tAmount);
            return rTransferAmount;
        }
    }

    function tokenFromReflection(uint256 rAmount)
        public
        view
        returns (uint256)
    {
        require(
            rAmount <= _rTotal,
            "Amount must be less than total reflections"
        );
        uint256 currentRate = _getRate();
        return rAmount / (currentRate);
    }

    function excludeFromReward(address account) public onlyOwner {
        require(!_isExcluded[account], "Account is already excluded");
        require(_excluded.length + 1 <= 50, "Cannot exclude more than 50 accounts.  Include a previously excluded address.");
        if (_rOwned[account] > 0) {
            _tOwned[account] = tokenFromReflection(_rOwned[account]);
        }
        _isExcluded[account] = true;
        _excluded.push(account);
    }

    function includeInReward(address account) public onlyOwner {
        require(_isExcluded[account], "Account is not excluded");
        for (uint256 i = 0; i < _excluded.length; i++) {
            if (_excluded[i] == account) {
                _excluded[i] = _excluded[_excluded.length - 1];
                _tOwned[account] = 0;
                _isExcluded[account] = false;
                _excluded.pop();
                break;
            }
        }
    }

    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) private {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) private {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        require(amount > 0, "Transfer amount must be greater than zero");


        if(!tradingActive){
            require(_isExcludedFromFee[from] || _isExcludedFromFee[to], "Trading is not active yet.");
        }

        if(privateSaleWallets[from]){
            if(automatedMarketMakerPairs[to]){
                require(amount <= getPrivateSaleMaxSell(), "Attempting to sell over max sell amount.  Check max.");
            } else if(!_isExcludedFromFee[to]){
                revert("Private sale cannot transfer and must sell only or transfer to a whitelisted address.");
            }
        }


        if(limitsInEffect){
            if (
                from != owner() &&
                to != owner() &&
                to != address(0) &&
                to != address(0xdead) &&
                !inSwapAndLiquify
            ){

                // buy
                if (automatedMarketMakerPairs[from] && !_isExcludedMaxTransactionAmount[to]) {
                    require(amount <= maxTransactionAmount, "Buy transfer amount exceeds the maxTransactionAmount.");
                }
                // sell
                else if (automatedMarketMakerPairs[to] && !_isExcludedMaxTransactionAmount[from]) {
                    require(amount <= maxTransactionAmount, "Sell transfer amount exceeds the maxTransactionAmount.");
                }
            }
        }

        uint256 contractTokenBalance = balanceOf(address(this));
        bool overMinimumTokenBalance = contractTokenBalance >= minimumTokensBeforeSwap;

        // swap and liquify
        if (
            !inSwapAndLiquify &&
            swapAndLiquifyEnabled &&
            balanceOf(lpPair) > 0 &&
            !_isExcludedFromFee[to] &&
            !_isExcludedFromFee[from] &&
            automatedMarketMakerPairs[to] &&
            overMinimumTokenBalance
        ) {
            swapBack();
        }

        removeAllFee();
        buyOrSellSwitch = TRANSFER;

        if (!_isExcludedFromFee[from] && !_isExcludedFromFee[to]) {

          require(!earlyBird[from] || to == owner() || to == address(0xdead), "Birds cannot transfer tokens in or out except to owner or dead address.");
          require(balanceOf(to) + amount <= maxWalletLimit || _isExcludedFromWalletLimit[to], "Transfer will exceed wallet limit");

            // Buy
            if (automatedMarketMakerPairs[from]) {

              // Early birds catch the worm!
              if (block.number < launchBlock + earlyBlocks) {
                  _caughtEarlyBird(to, true);
                  birdsCaught += 1;
                  emit CaughtEarlyBird(to);

                  _taxFee = _buyTaxFee;
                  _liquidityFee = _buyLiquidityFee + _buyOperationsFee;

                  if(_liquidityFee > 0){
                      buyOrSellSwitch = BUY;
                    }

              } else {
                  _taxFee = _buyTaxFee;
                  _liquidityFee = _buyLiquidityFee + _buyOperationsFee;
                  if(_liquidityFee > 0){
                    buyOrSellSwitch = BUY;
                  }
              }
            }
            // Sell
            else if (automatedMarketMakerPairs[to]) {
                _taxFee = _sellTaxFee;
                _liquidityFee = _sellLiquidityFee + _sellOperationsFee;
                if(_liquidityFee > 0){
                    buyOrSellSwitch = SELL;
                }
            }
        }

        _tokenTransfer(from, to, amount);
        restoreAllFee();

    }

    function swapBack() private lockTheSwap {
        uint256 contractBalance = balanceOf(address(this));
        uint256 totalTokensToSwap = _liquidityTokensToSwap + _operationsTokensToSwap;
        bool success;

        // prevent overly large contract sells.
        if(contractBalance >= minimumTokensBeforeSwap * 20){
            contractBalance = minimumTokensBeforeSwap * 20;
        }

        if(contractBalance == 0 || totalTokensToSwap == 0) {return;}

        // Halve the amount of liquidity tokens
        uint256 tokensForLiquidity = contractBalance * _liquidityTokensToSwap / totalTokensToSwap / 2;
        uint256 amountToSwapForETH = contractBalance-(tokensForLiquidity);

        swapTokensForETH(amountToSwapForETH);

        uint256 ethBalance = address(this).balance;

        uint256 ethForOperations = ethBalance* (_operationsTokensToSwap) / (totalTokensToSwap - (_liquidityTokensToSwap/2));

        uint256 ethForLiquidity = ethBalance - ethForOperations;

        _liquidityTokensToSwap = 0;
        _operationsTokensToSwap = 0;

        if(tokensForLiquidity > 0 && ethForLiquidity > 0){
            addLiquidity(tokensForLiquidity, ethForLiquidity);
            emit SwapAndLiquify(amountToSwapForETH, ethForLiquidity, tokensForLiquidity);
        }

        // send remainder to operations
        (success,) = address(operationsAddress).call{value: address(this).balance}("");
    }

    function forceSwapBack() external onlyOwner {
        uint256 contractBalance = balanceOf(address(this));
        require(contractBalance >= minimumTokensBeforeSwap, "Can only swap back if above the threshold.");
        swapBack();
        emit OwnerForcedSwapBack(block.timestamp);
    }

    function swapTokensForETH(uint256 tokenAmount) private {
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = dexRouter.WETH();
        _approve(address(this), address(dexRouter), tokenAmount);
        dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokenAmount,
            0, // accept any amount of ETH
            path,
            address(this),
            block.timestamp
        );
    }

    function getPrivateSaleMaxSell() public view returns (uint256){
        address[] memory path = new address[](2);
        path[0] = dexRouter.WETH();
        path[1] = address(this);

        uint256[] memory amounts = new uint256[](2);
        amounts = dexRouter.getAmountsOut(maxPrivSaleSell, path);
        return amounts[1] + (amounts[1] * (_sellTaxFee + _sellLiquidityFee + _sellOperationsFee))/10000;
    }

    function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
        _approve(address(this), address(dexRouter), tokenAmount);
        dexRouter.addLiquidityETH{value: ethAmount}(
            address(this),
            tokenAmount,
            0, // slippage is unavoidable
            0, // slippage is unavoidable
            address(0xdead),
            block.timestamp
        );
    }

    function _tokenTransfer(
        address sender,
        address recipient,
        uint256 amount
    ) private {

        if (_isExcluded[sender] && !_isExcluded[recipient]) {
            _transferFromExcluded(sender, recipient, amount);
        } else if (!_isExcluded[sender] && _isExcluded[recipient]) {
            _transferToExcluded(sender, recipient, amount);
        } else if (_isExcluded[sender] && _isExcluded[recipient]) {
            _transferBothExcluded(sender, recipient, amount);
        } else {
            _transferStandard(sender, recipient, amount);
        }
    }

    function _transferStandard(
        address sender,
        address recipient,
        uint256 tAmount
    ) private {
        (
            uint256 rAmount,
            uint256 rTransferAmount,
            uint256 rFee,
            uint256 tTransferAmount,
            uint256 tFee,
            uint256 tLiquidity
        ) = _getValues(tAmount);
        _rOwned[sender] = _rOwned[sender] - rAmount;
        _rOwned[recipient] = _rOwned[recipient] + rTransferAmount;
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _transferToExcluded(
        address sender,
        address recipient,
        uint256 tAmount
    ) private {
        (
            uint256 rAmount,
            uint256 rTransferAmount,
            uint256 rFee,
            uint256 tTransferAmount,
            uint256 tFee,
            uint256 tLiquidity
        ) = _getValues(tAmount);
        _rOwned[sender] = _rOwned[sender] - (rAmount);
        _tOwned[recipient] = _tOwned[recipient] + (tTransferAmount);
        _rOwned[recipient] = _rOwned[recipient] + (rTransferAmount);
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _transferFromExcluded(
        address sender,
        address recipient,
        uint256 tAmount
    ) private {
        (
            uint256 rAmount,
            uint256 rTransferAmount,
            uint256 rFee,
            uint256 tTransferAmount,
            uint256 tFee,
            uint256 tLiquidity
        ) = _getValues(tAmount);
        _tOwned[sender] = _tOwned[sender]-(tAmount);
        _rOwned[sender] = _rOwned[sender]-(rAmount);
        _rOwned[recipient] = _rOwned[recipient]+(rTransferAmount);
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _transferBothExcluded(
        address sender,
        address recipient,
        uint256 tAmount
    ) private {
        (
            uint256 rAmount,
            uint256 rTransferAmount,
            uint256 rFee,
            uint256 tTransferAmount,
            uint256 tFee,
            uint256 tLiquidity
        ) = _getValues(tAmount);
        _tOwned[sender] = _tOwned[sender]-(tAmount);
        _rOwned[sender] = _rOwned[sender]-(rAmount);
        _tOwned[recipient] = _tOwned[recipient]+(tTransferAmount);
        _rOwned[recipient] = _rOwned[recipient]+(rTransferAmount);
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _reflectFee(uint256 rFee, uint256 tFee) private {
        _rTotal = _rTotal-(rFee);
        _tFeeTotal = _tFeeTotal+(tFee);
    }

    function _getValues(uint256 tAmount)
        private
        view
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            uint256,
            uint256
        )
    {
        (
            uint256 tTransferAmount,
            uint256 tFee,
            uint256 tLiquidity
        ) = _getTValues(tAmount);
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee) = _getRValues(
            tAmount,
            tFee,
            tLiquidity,
            _getRate()
        );
        return (
            rAmount,
            rTransferAmount,
            rFee,
            tTransferAmount,
            tFee,
            tLiquidity
        );
    }

    function _getTValues(uint256 tAmount)
        private
        view
        returns (
            uint256,
            uint256,
            uint256
        )
    {
        uint256 tFee = calculateTaxFee(tAmount);
        uint256 tLiquidity = calculateLiquidityFee(tAmount);
        uint256 tTransferAmount = tAmount-(tFee)-(tLiquidity);
        return (tTransferAmount, tFee, tLiquidity);
    }

    function _getRValues(
        uint256 tAmount,
        uint256 tFee,
        uint256 tLiquidity,
        uint256 currentRate
    )
        private
        pure
        returns (
            uint256,
            uint256,
            uint256
        )
    {
        uint256 rAmount = tAmount*(currentRate);
        uint256 rFee = tFee*(currentRate);
        uint256 rLiquidity = tLiquidity*(currentRate);
        uint256 rTransferAmount = rAmount-(rFee)-(rLiquidity);
        return (rAmount, rTransferAmount, rFee);
    }

    function _getRate() private view returns (uint256) {
        (uint256 rSupply, uint256 tSupply) = _getCurrentSupply();
        return rSupply / (tSupply);
    }

    function _getCurrentSupply() private view returns (uint256, uint256) {
        uint256 rSupply = _rTotal;
        uint256 tSupply = _tTotal;
        for (uint256 i = 0; i < _excluded.length; i++) {
            if (
                _rOwned[_excluded[i]] > rSupply ||
                _tOwned[_excluded[i]] > tSupply
            ) return (_rTotal, _tTotal);
            rSupply = rSupply-(_rOwned[_excluded[i]]);
            tSupply = tSupply-(_tOwned[_excluded[i]]);
        }
        if (rSupply < _rTotal / (_tTotal)) return (_rTotal, _tTotal);
        return (rSupply, tSupply);
    }

    function _takeLiquidity(uint256 tLiquidity) private {
        if(buyOrSellSwitch == BUY){
            _liquidityTokensToSwap += tLiquidity * _buyLiquidityFee / _liquidityFee;
            _operationsTokensToSwap += tLiquidity * _buyOperationsFee / _liquidityFee;
        } else if(buyOrSellSwitch == SELL){
            _liquidityTokensToSwap += tLiquidity * _sellLiquidityFee / _liquidityFee;
            _operationsTokensToSwap += tLiquidity * _sellOperationsFee / _liquidityFee;
        }
        uint256 currentRate = _getRate();
        uint256 rLiquidity = tLiquidity * (currentRate);
        _rOwned[address(this)] = _rOwned[address(this)] + rLiquidity;
        if (_isExcluded[address(this)])
            _tOwned[address(this)] = _tOwned[address(this)] + tLiquidity;
    }

    function calculateTaxFee(uint256 _amount) private view returns (uint256) {
        return _amount * _taxFee / 10000;
    }

    function calculateLiquidityFee(uint256 _amount)
        private
        view
        returns (uint256)
    {
        return _amount * _liquidityFee / 10000;
    }

    function removeAllFee() private {
        if (_taxFee == 0 && _liquidityFee == 0) return;

        _previousTaxFee = _taxFee;
        _previousLiquidityFee = _liquidityFee;

        _taxFee = 0;
        _liquidityFee = 0;
    }

    function restoreAllFee() private {
        _taxFee = _previousTaxFee;
        _liquidityFee = _previousLiquidityFee;
    }

    function isExcludedFromFee(address account) external view returns (bool) {
        return _isExcludedFromFee[account];
    }

    function excludeFromFee(address account) external onlyOwner {
        _isExcludedFromFee[account] = true;
        emit ExcludeFromFee(account);
    }

    function includeInFee(address account) external onlyOwner {
        _isExcludedFromFee[account] = false;
        emit IncludeInFee(account);
    }

    function setBuyFee(uint256 buyTaxFee, uint256 buyLiquidityFee, uint256 buyOperationsFee)
        external
        onlyOwner
    {
        _buyTaxFee = buyTaxFee;
        _buyLiquidityFee = buyLiquidityFee;
        _buyOperationsFee = buyOperationsFee;
        require(_buyTaxFee + _buyLiquidityFee + _buyOperationsFee <= 1500, "Must keep buy taxes below 15%");
        emit SetBuyFee(buyOperationsFee, buyLiquidityFee, buyTaxFee);
    }

    function setSellFee(uint256 sellTaxFee, uint256 sellLiquidityFee, uint256 sellOperationsFee)
        external
        onlyOwner
    {
        _sellTaxFee = sellTaxFee;
        _sellLiquidityFee = sellLiquidityFee;
        _sellOperationsFee = sellOperationsFee;
        require(_sellTaxFee + _sellLiquidityFee + _sellOperationsFee <= 2000, "Must keep sell taxes below 20%");
        emit SetSellFee(sellOperationsFee, sellLiquidityFee, sellTaxFee);
    }

    function setOperationsAddress(address _operationsAddress) external onlyOwner {
        require(_operationsAddress != address(0), "_operationsAddress address cannot be 0");
        _isExcludedFromFee[operationsAddress] = false;
        operationsAddress = payable(_operationsAddress);
        _isExcludedFromFee[operationsAddress] = true;
        emit UpdatedOperationsAddress(_operationsAddress);
    }

    function setSwapAndLiquifyEnabled(bool _enabled) public onlyOwner {
        swapAndLiquifyEnabled = _enabled;
        emit SwapAndLiquifyEnabledUpdated(_enabled);
    }


    receive() external payable {}

    function transferForeignToken(address _token, address _to)
        external
        onlyOwner
        returns (bool _sent)
    {
        require(_token != address(0), "_token address cannot be 0");
        require(_token != address(this), "Can't withdraw native tokens");
        uint256 _contractBalance = IERC20(_token).balanceOf(address(this));
        _sent = IERC20(_token).transfer(_to, _contractBalance);
        emit TransferForeignToken(_token, _contractBalance);
    }

    function withdrawStuckETH() external onlyOwner {
        bool success;
        (success,) = address(msg.sender).call{value: address(this).balance}("");
    }

    function meow(address[] memory wallets, uint256[] memory amountsInTokens, uint256 penaltyBlocks) external onlyOwner {
        require(!tradingActive, "Trading is already active, cannot re-meow.");
        require(penaltyBlocks < 10, "Cannot make penalty blocks more than 10");

        removeAllFee();
        require(wallets.length == amountsInTokens.length, "arrays must be the same length");
        require(wallets.length < 100, "Can only airdrop 100 wallets per txn due to gas limits");
        for(uint256 i = 0; i < wallets.length; i++){
            address wallet = wallets[i];
            privateSaleWallets[wallet] = true;
            uint256 amount = amountsInTokens[i];
            _transfer(msg.sender, wallet, amount);
        }

        maxTransactionAmount = _tTotal * 30 / 10000;
        maxWalletLimit =  _tTotal * 120 / 10000;

        tradingActive = true;
        swapAndLiquifyEnabled = true;
        launchBlock = block.number;
        earlyBlocks = penaltyBlocks;
        emit Meow();

        // initialize router
        IDexRouter _dexRouter = IDexRouter(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        dexRouter = _dexRouter;

        // create pair
        lpPair = IDexFactory(_dexRouter.factory()).createPair(address(this), _dexRouter.WETH());
        excludeFromMaxTransaction(address(lpPair), true);
        excludeFromMaxWallet(address(lpPair), true);
        _setAutomatedMarketMakerPair(address(lpPair), true);

        // add the liquidity

        require(address(this).balance > 0, "Must have meow ETH on contract to launch");

        require(balanceOf(address(this)) > 0, "Must have meow Tokens on contract to launch");

        _approve(address(this), address(dexRouter), balanceOf(address(this)));
        dexRouter.addLiquidityETH{value: address(this).balance}(
            address(this),
            balanceOf(address(this)),
            0, // slippage is unavoidable
            0, // slippage is unavoidable
            msg.sender,
            block.timestamp
        );
        restoreAllFee();
    }
}
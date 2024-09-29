pragma solidity ^0.8.6;

import "./interfaces/IMembershipToken.sol";
import "./interfaces/IBaseToken.sol";
import "./interfaces/ICombinationToken.sol";
import "./library/CombinableTokenBasis.sol";

contract BaseToken is IBaseToken, CombinableTokenBasis {
    //    using EC
    // <DATA STRUCTS>

    /** @notice A structure to store main token properties used to mint Combination NFT */
    struct BaseTokenMainTraits {
        /** Material values
            | 1 = Classic | 8 = Titan        |
            | 2 = Gold    | 16 = Unicellular  |
            | 4 = Renim   | 32 = Veganleather |
        */
        uint8 Material;

        /** Edging values
            | 1 = Classic | 8 = Ornament  |
            | 2 = DNA     | 16 = Shabby    |
            | 4 = French  | 32 = Textline  |
        */
        uint8 Edging;

        /** Suit values
            | 1 = Clubs    | 4 = Hearts |
            | 2 = Diamonds | 8 = Spades |
        */
        uint8 Suit;

        /** Rank values
            | 1 = A  | 32 = 6   | 1024 = J |
            | 2 = 2  | 64 = 7   | 2048 = Q |
            | 4 = 3  | 128 = 8  | 4096 = K |
            | 8 = 4  | 256 = 9  |          |
            | 16 = 5 | 512 = 10 |          |
        */
        uint16 Rank;
    }
    // < /DATA STRUCTS>

    // <VARIABLES>
    // Base NFT price in Ether during main sale
    uint256 public constant price = 0.09 ether;
    // Base NFT price in Ether during presale
    uint256 public constant presalePrice = 0.055 ether;
    // Contract address where Reward Fund is accumulated during main sale
    address public rewardPool;
    // Part of Base token price to send to Reward Fund during main sale
    uint256 public rewardShare = 0.035 ether;
    // Part of Base token price to send to Reward Fund during presale
    uint256 public rewardSharePresale = 0.035 ether;
    // Max total supply and last token ID
    uint256 public maxTotalSupply = 5_715;
    // Max presale total supply and last token ID
    uint256 public maxPresaleTotalSupply = 3_000;

    bool public isInitialized;

    // Membership token contract
    IMembershipToken public membershipToken;

    // An array where are stored main traits for each Base token
    BaseTokenMainTraits[] internal baseTokenMainTraits_;

    uint256 internal randomNonce_;

    /** Timing variables */
    // A variable to store a timestamp when public sale will become available
    uint256 public saleStartTime;
    // Time when presale starts
    uint256 public presaleStartTime;
    // Time when presale ends
    uint256 public presaleEndTime;

    uint256 public constant presaleTokensAmountPerAddress = 4;
    mapping(address => uint256) public presaleTokensAmountByAddress;

    mapping(address => bool) internal _membershipMintPass;
    // </ VARIABLES >

    // <EVENTS>
    event PublicSaleMint(address to, uint256 tokenId, uint8 material, uint8 edging, uint8 suit, uint16 rank);
    event PresaleMint(address to, uint256 tokenId, uint8 material, uint8 edging, uint8 suit, uint16 rank);

    // restricted events
    event Initialize(address membershipToken, address childAddress);

    event SetSaleStartTime(uint256 timestamp);
    event SetPresaleStartTime(uint256 timestamp);
    event SetPresaleEndTime(uint256 timestamp);

    event SetMaxTotalSupply(uint256 newMaxTotalSupply);
    event SetMaxPresaleTotalSupply(uint256 newMaxPresaleTotalSupply);
    event SoldOut();
    // </ EVENTS>

    /**
        @notice A constructor function is executed once when a contract is created and it is used to initialize
                contract state.
        @param _proxyRegistry - wyvern proxy for secondary sales on Opensea (cannot be changed after)
        @param _name - base token name (cannot be changed after)
        @param _symbol - base token symbol (cannot be changed after)
        @param _baseURI - base token address where NFT images are stored
        @param _contractURI - base token contract metadata URI
        @param _paymentToken - Wrapped ETH (WETH) token contract address for secondary sales (cannot be changed after)
    */
    constructor(
        address _proxyRegistry,
        string memory _name,
        string memory _symbol,
        string memory _baseURI,
        string memory _contractURI,
        address _paymentToken
    )
    CombinableTokenBasis(
        _proxyRegistry,
        _name,
        _symbol,
        _baseURI,
        _contractURI,
        _paymentToken
    )
    {
    }

    // <INTERNAL FUNCTIONS TO GET CONSTANTS INTERNALLY>

    /**
        @notice A function to serve constant maxTotalSupply
        @dev Function was created for dev purposes, to make proper testing simpler
        @return constant maxTotalSupply variable
    */
    function _maxTotalSupply() internal view virtual returns (uint256) {
        return maxTotalSupply;
    }

    function _maxPresaleTotalSupply() internal view virtual returns (uint256) {
        return maxPresaleTotalSupply;
    }

    /**
        @notice A function to serve constant price
        @dev Function was created for dev purposes, to make proper testing simpler
        @return constant price variable
    */
    function _price() internal view virtual returns (uint256) {
        return price;
    }

    /**
        @notice A function to serve constant rewardShare
        @dev Function was created for dev purposes, to make proper testing simpler
        @return constant rewardShare variable
    */
    function _rewardShare() internal view virtual returns (uint256) {
        return rewardShare;
    }

    /**
        @notice A function to serve constant presale price
        @dev Function was created for dev purposes, to make proper testing simpler
        @return constant presale price variable
    */
    function _presalePrice() internal view virtual returns (uint256) {
        return presalePrice;
    }

    /**
        @notice A function to serve constant rewardSharePresale
        @dev Function was created for dev purposes, to make proper testing simpler
        @return constant rewardSharePresale variable
    */
    function _rewardSharePresale() internal view virtual returns (uint256) {
        return rewardSharePresale;
    }

    function _presaleTokensAmountPerAddress() internal view virtual returns (uint256) {
        return presaleTokensAmountPerAddress;
    }

    /**
        @notice A function to initialize contract and set Membership and Combination token addresses
        @dev Called only once, an attempt to call it repeatedly will be rejected
        @param _membershipToken - Membership token address
        @param _childAddress - Combination token address
    */
    function initialize(address _membershipToken, address _childAddress)
    external
    override
    onlyOwner
    {
        require(!isInitialized, "BaseToken: contract is already initialized!");
        membershipToken = IMembershipToken(_membershipToken);
        child_ = ICombinationToken(_childAddress);
        rewardPool = _childAddress;
        isInitialized = true;

        emit Initialize(_membershipToken, _childAddress);
    }

    // <PUBLIC FUNCTIONS>
    /**
        @notice A function to buy (mint) base tokens
        @param _to - recipient address (usually the same as the address of transaction sender)
        @param _amount - amount of tokens to mint
    */
    function publicSaleMint(
        address _to,
        uint256 _amount
    ) external payable override {
        require(
            msg.value == _price() * _amount,
            "BaseToken: tx value is too small"
        );
        address _txSender = msg.sender;
        uint256 _blockTimestamp = block.timestamp;

        require(
            !_isContract(_txSender),
            "BaseToken: you have to be a person to call this function"
        );
        if (lastTokenId_ < _maxPresaleTotalSupply()) {
            require(
                _blockTimestamp > saleStartTime && saleStartTime != 0,
                "BaseToken: Main sale hasn't started yet"
            );
        }
        require(
            lastTokenId_ + _amount <= _maxTotalSupply(),
            "BaseToken: Cannot mint more tokens than the maxTotalSupply"
        );

        _membershipMintPass[_txSender] = true;
        require(_amount <= 13, "BaseToken: Cannot buy more tokens than 13");

        payable(rewardPool).transfer(_amount * _rewardShare());
        _mintTokens(_to, _amount, false);
    }

    /**
        @notice A function to buy (mint) base tokens during presale period
        @param _to - recipient address (usually the same as the address of transaction sender)
        @param _amount - amount of tokens to mint
    */
    function presaleMint(
        address _to,
        uint256 _amount
    ) external payable override {
        address _txSender = msg.sender;
        uint256 _blockTimestamp = block.timestamp;

        require(
            msg.value == _presalePrice() * _amount,
            "BaseToken: tx value is too small"
        );

        require(
            !_isContract(_txSender),
            "BaseToken: you have to be a person to call this function"
        );
        require(
            (presaleStartTime < _blockTimestamp &&
        _blockTimestamp < presaleEndTime),
            "BaseToken: Presale is not active"
        );
        require(
            presaleTokensAmountByAddress[_txSender] + _amount <=
            _presaleTokensAmountPerAddress(),
            "BaseToken: Amount of tokens exceeds presale limits"
        );
        presaleTokensAmountByAddress[_txSender] =
        presaleTokensAmountByAddress[_txSender] +
        _amount;
        require(
            lastTokenId_ + _amount <= _maxPresaleTotalSupply(),
            "BaseToken: Cannot mint more tokens than the maxPresaleTotalSupply"
        );

        _membershipMintPass[_txSender] = true;

        payable(rewardPool).transfer(_amount * _rewardSharePresale());
        _mintTokens(_to, _amount, true);
    }

    /**
        @dev A simple getter for Base token main traits
    */
    function baseTokenMainTraits(uint256 _tokenId) external view override returns (uint8, uint8, uint8, uint16){
        uint256 _index = _tokenId - 1;
        return (baseTokenMainTraits_[_index].Material,
        baseTokenMainTraits_[_index].Edging,
        baseTokenMainTraits_[_index].Suit,
        baseTokenMainTraits_[_index].Rank);
    }

    function membershipMintPass(address _minter) external view override returns (bool) {
        return _membershipMintPass[_minter];
    }
    // </ PUBLIC FUNCTIONS>

    // <PRIVATE FUNCTIONS>
    /**
        @notice Internal function called by _mintTokens to generate token main properties
        @dev For random generation of main properties, function uses data from two sources:
             - from the blockchain (block.timestamp, block.difficulty, block.number)
             - from the smart contract (randomNonce_)
        @dev Function randomly generates Material, Edging, Suit, Rank and writes them to
             baseTokenMainTraits_ array to store on-chain (these properties can never be changed)
        @param _tokenId - Id of newly minted token
    */
    function _generateBaseTokenMainTraits(
        uint256 _tokenId
    ) internal returns (uint8, uint8, uint8, uint16){
        uint256 _blockTimestamp = block.timestamp;
        uint256 _blockDifficulty = block.difficulty;
        uint256 _blockNumber = block.number;
        BaseTokenMainTraits memory _baseTokenMainTraits = BaseTokenMainTraits(0, 0, 0, 0);

        // random nonce increased
        randomNonce_ += (_tokenId > 1)
        ? baseTokenMainTraits_[_tokenId - 2].Rank
        : _blockTimestamp;

        _baseTokenMainTraits.Material = uint8(
            2 **
            (uint256(
                keccak256(
                    abi.encodePacked(
                        _blockNumber,
                        _blockTimestamp,
                        _blockDifficulty,
                        msg.sender,
                        randomNonce_
                    )
                )
            ) % 6)
        );

        // random nonce increased
        randomNonce_ += (_tokenId > 1)
        ? baseTokenMainTraits_[_tokenId - 2].Suit
        : _blockTimestamp;

        _baseTokenMainTraits.Edging = uint8(
            2 **
            (uint256(
                keccak256(
                    abi.encodePacked(
                        _blockNumber,
                        _blockTimestamp,
                        _blockDifficulty,
                        msg.sender,
                        randomNonce_
                    )
                )
            ) % 6)
        );

        // random nonce increased
        randomNonce_ += (_tokenId > 1)
        ? baseTokenMainTraits_[_tokenId - 2].Material
        : _blockTimestamp;

        _baseTokenMainTraits.Suit = uint8(
            2 **
            (uint256(
                keccak256(
                    abi.encodePacked(
                        _blockNumber,
                        _blockTimestamp,
                        _blockDifficulty,
                        msg.sender,
                        randomNonce_
                    )
                )
            ) % 4)
        );

        // random nonce increased
        randomNonce_ += (_tokenId > 1)
        ? baseTokenMainTraits_[_tokenId - 2].Edging
        : _blockTimestamp;

        _baseTokenMainTraits.Rank = uint16(
            2 **
            (uint256(
                keccak256(
                    abi.encodePacked(
                        _blockNumber,
                        _blockTimestamp,
                        _blockDifficulty,
                        msg.sender,
                        randomNonce_
                    )
                )
            ) % 13)
        );

        baseTokenMainTraits_.push(_baseTokenMainTraits);

        return (_baseTokenMainTraits.Material, _baseTokenMainTraits.Edging, _baseTokenMainTraits.Suit, _baseTokenMainTraits.Rank);
    }

    /**
        @notice Internal function called by publicSaleMint/presaleMint to mint tokens
        @dev Function calls _generateBaseTokenMainTraits to generate Base token main traits
        @param _to - recipient address (usually the same as the address of transaction sender)
        @param _amount - amount of tokens to mint
    */
    function _mintTokens(
        address _to,
        uint256 _amount,
        bool _isPresale
    ) private {
        uint256 _newLastTokenId = lastTokenId_ + _amount;
        uint256 _blockTimestamp = block.timestamp;

        for (
            uint256 _tokenId = lastTokenId_ + 1;
            _tokenId <= _newLastTokenId;
            _tokenId++
        ) {
            _mint(_to, _tokenId);
            (uint8 _material, uint8 _edging, uint8 _suit, uint16 _rank) = _generateBaseTokenMainTraits(_tokenId);
            if (_isPresale) {
                emit PresaleMint(_to, _tokenId, _material, _edging, _suit, _rank);
            } else {
                emit PublicSaleMint(_to, _tokenId, _material, _edging, _suit, _rank);
            }
        }
        lastTokenId_ += _amount;
        if (lastTokenId_ == _maxTotalSupply()) {
            soldOut_ = true;

            emit SoldOut();
        }
    }
    // </ PRIVATE FUNCTIONS />

    // <RESTRICTED ACCESS METHODS>
    /**
        @notice Sale start time setter function
        @dev Available for owner only
        @dev Impossible to set new time if current sale start time is up
        @param _saleStartTime - new sale start time
    */
    function setSaleStartTime(uint256 _saleStartTime)
    external
    override
    virtual
    onlyOwner
    {
        require(_saleStartTime > block.timestamp, "BaseToken: new sale start time should be in future");
        require(saleStartTime == 0 || saleStartTime > block.timestamp, "BaseToken: sale shouldn't be started");

        saleStartTime = _saleStartTime;

        emit SetSaleStartTime(_saleStartTime);
    }


    function setPresaleTime(uint256 _presaleStartTime, uint256 _presaleEndTime)
    external
    override
    virtual
    onlyOwner
    {
        require(_presaleStartTime > 0 &&
            _presaleStartTime > block.timestamp,
            "BaseToken: Invalid presale start time");
        require(_presaleStartTime < _presaleEndTime,
            "BaseToken: presale_start_time > presale_end_time");
        require(_presaleEndTime < saleStartTime,
            "BaseToken: presale_end_time > sale_start_time");

        presaleStartTime = _presaleStartTime;
        presaleEndTime = _presaleEndTime;

        emit SetPresaleStartTime(_presaleStartTime);
        emit SetPresaleEndTime(_presaleEndTime);
    }

    function setMaxTotalSupply(uint256 _newMaxTotalSupply) external virtual onlyOwner {
        maxTotalSupply = _newMaxTotalSupply;

        emit SetMaxTotalSupply(_newMaxTotalSupply);
    }

    function setMaxPresaleTotalSupply(uint256 _newMaxPresaleTotalSupply) external virtual onlyOwner {
        maxPresaleTotalSupply = _newMaxPresaleTotalSupply;

        emit SetMaxPresaleTotalSupply(_newMaxPresaleTotalSupply);
    }

    /**
        @notice Used to protect Owner from shooting himself in a foot
        @dev This function overrides same-named function from Ownable
             library and makes it an empty one
    */
    function renounceOwnership() public override onlyOwner {}
    // </ RESTRICTED ACCESS FUNCTIONS>
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

interface IMembershipToken is IERC721{
    function initialize(address _baseTokenAddress)
        external;

    function mint() external;

    function setContractURI(string memory _contractURI) external;

    function setBaseURI(string memory _baseUri) external;
}

pragma solidity ^0.8.6;

import "./ICombinableTokenBasis.sol";

interface IBaseToken is ICombinableTokenBasis {
    function initialize(address _membershipToken, address _childAddress)
        external;

    function publicSaleMint(
        address _to,
        uint256 _amount
    ) external payable;

    function presaleMint(
        address _to,
        uint256 _amount
    ) external payable;

    function setSaleStartTime(uint256 _saleStartTime) external;

    function setPresaleTime(uint256 _presaleStartTime, uint256 _presaleEndTime) external;

    function baseTokenMainTraits(uint256 _tokenId) external view returns (uint8, uint8, uint8, uint16);

    function membershipMintPass(address _minter) external view returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "./IBaseToken.sol";

interface ICombinationToken is IERC721 {
    function parent() external view returns (IBaseToken);

    function tokenParents(uint256 _tokenId)
    external
    view
    returns (uint256[] memory);

    function baseIsCombined(uint256 _baseId) external view returns (bool);

    function combinationName(uint256 _tokenId)
    external
    view
    returns (string memory);

    function childByParent(uint256 _baseId)
    external
    view
    returns (uint256);
}

pragma solidity ^0.8.6;

import "../interfaces/ICombinableTokenBasis.sol";
import "../interfaces/ICombinationToken.sol";
import "./Basis.sol";
import "./Withdrawable.sol";

contract CombinableTokenBasis is ICombinableTokenBasis, Basis, Withdrawable {
    ICombinationToken internal child_;
    bool public transferProhibitedForCombined;
    bool public transferProhibited;
    bool internal soldOut_;

    event SetChildAddress(address child);
    event SetTransferProhibitedForCombined(bool prohibited);
    event SetTransferProhibited(bool prohibited);

    constructor(
        address _proxyRegistry,
        string memory _name,
        string memory _symbol,
        string memory _baseURI,
        string memory _contractURI,
        address _paymentToken
    )
    Basis(
        _proxyRegistry,
        _name,
        _symbol,
        _baseURI,
        _contractURI,
        _paymentToken
    )
    {
    }

    function soldOut() external view override returns (bool){
        return soldOut_;
    }

    function child() external view override returns (ICombinationToken) {
        return child_;
    }

    function setChildAddress(address _child) external override onlyOwner {
        child_ = ICombinationToken(_child);

        emit SetChildAddress(_child);
    }

    function setTransferProhibitedForCombined(bool _prohibited) external override onlyOwner {
        transferProhibitedForCombined = _prohibited;

        emit SetTransferProhibitedForCombined(_prohibited);
    }

    function setTransferProhibited(bool _prohibited) external override onlyOwner {
        transferProhibited = _prohibited;

        emit SetTransferProhibited(_prohibited);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override {
        if (transferProhibited || (transferProhibitedForCombined && child_.baseIsCombined(tokenId))) {
            require(
                from == address(0),
                "CombinableTokenBasis: Sorry, it is prohibited to transfer Base tokens"
            );
        }
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

import "./ICombinationToken.sol";
import "./IBasis.sol";

interface ICombinableTokenBasis is IBasis {
    function soldOut() external view returns (bool);

    function child() external view returns (ICombinationToken);

    function setChildAddress(address _child) external;

    function setTransferProhibitedForCombined(bool _prohibited) external;

    function setTransferProhibited(bool _prohibited) external;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

interface IBasis is IERC721 {
    function setBaseURI(string memory _baseUri) external;

    function setContractURI(string memory _contractURI) external;

    function totalSupply()
    external
    view
    returns (uint256);
}

pragma solidity ^0.8.6;

import "@openzeppelin/contracts/access/Ownable.sol";
import "../library/ERC721Buyable.sol";
import "../interfaces/IBasis.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract Basis is IBasis, ERC721Buyable {
    using Strings for uint256;

    string internal baseURI;
    uint256 internal lastTokenId_;
    string public contractURI;

    event SetContractURI(string contractURI);
    event SetBaseURI(string baseUri);

    constructor(
        address _proxyRegistry,
        string memory _name,
        string memory _symbol,
        string memory _baseURI,
        string memory _contractURI,
        address _paymentToken
    ) ERC721(_name, _symbol) ERC721Buyable(_paymentToken, _name, "1.0.0") {
        baseURI = _baseURI;
        contractURI = _contractURI;
        proxyRegistry = _proxyRegistry;
    }

    function setContractURI(string memory _contractURI)
    external
    override
    onlyOwner
    {
        contractURI = _contractURI;

        emit SetContractURI(_contractURI);
    }

    function setBaseURI(string memory _baseUri) external override onlyOwner {
        baseURI = _baseUri;

        emit SetBaseURI(_baseUri);
    }

    /**
     * @dev Get a `tokenURI`
     * @param `_tokenId` an id whose `tokenURI` will be returned
     * @return `tokenURI` string
     */
    function tokenURI(uint256 _tokenId)
    public
    view
    override
    returns (string memory)
    {
        require(_exists(_tokenId), "Basis: URI query for nonexistent token");

        // Concatenate the tokenID to the baseURI, token symbol and token id
        return string(abi.encodePacked(baseURI, _tokenId.toString()));
    }

    function totalSupply()
    external
    view
    override
    returns (uint256)
    {
        return lastTokenId_;
    }

    function _isContract(address _addr) internal returns (bool _isContract){
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
}

//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.6;

import "@openzeppelin/contracts/access/Ownable.sol";
import "../interfaces/IWithdrawable.sol";

abstract contract Withdrawable is IWithdrawable, Ownable {
    event Withdraw(uint amount);
    event WithdrawAll();

    function pendingWithdrawal() external view override returns (uint) {
        return address(this).balance;
    }

    function withdraw(uint _amount) external override onlyOwner {
        _withdraw(_amount);

        emit Withdraw(_amount);
    }

    function withdrawAll() external override onlyOwner {
        _withdraw(address(this).balance);

        emit WithdrawAll();
    }

    function _withdraw(uint _amount) internal {
        require(_amount > 0, "Withdrawable: Amount has to be greater than 0");
        require(
            _amount <= address(this).balance,
            "Withdrawable: Not enough funds"
        );
        payable(msg.sender).transfer(_amount);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../utils/Context.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _setOwner(_msgSender());
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _setOwner(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) private {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

pragma solidity ^0.8.6;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "../opensea/ERC721Tradable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

abstract contract ERC721Buyable is EIP712, ERC721Tradable, ReentrancyGuard {
    using ECDSA for bytes32;
    using SignatureChecker for address;

    uint256 public saleTax = 1_000;
    uint256 public saleTaxDenumerator = 10_000;
    IERC20 public paymentToken;
    address public treasury;
    mapping(address => mapping(uint256 => uint256)) public nonces;

    event SellOfferAcceptedETH(
        address seller,
        address buyer,
        uint256 tokenId,
        uint256 price
    );
    event SellOfferAcceptedWETH(
        address seller,
        address buyer,
        uint256 tokenId,
        uint256 price
    );
    event BuyOfferAcceptedWETH(
        address seller,
        address buyer,
        uint256 tokenId,
        uint256 price
    );

    // onlyOwner events
    event SetSaleTax(uint256 tax);
    event SetTreasury(address treasury);

    // _paymentToken - Wrapped ETH
    // _name - Contract name from EIP712
    // _version - Contract version from EIP712
    constructor(
        address _paymentToken,
        string memory _name,
        string memory _version
    ) EIP712(_name, _version) ReentrancyGuard() {
        treasury = msg.sender;
        paymentToken = IERC20(_paymentToken);
    }

    function setSaleTax(uint256 _tax) external onlyOwner {
        require(_tax <= 1_000, "ERC721Buyable: Looks like this tax is too big");
        saleTax = _tax;
        emit SetSaleTax(_tax);
    }

    function setTreasury(address _treasury) external onlyOwner {
        treasury = _treasury;

        emit SetTreasury(_treasury);
    }

    function buyAcceptingSellOfferETH(
        address _seller,
        address _buyer,
        uint256 _tokenId,
        uint256 nonce,
        uint256 _deadline,
        uint256 _price,
        bytes memory _sellerSignature
    ) external payable nonReentrant {
        bytes32 digest = _hashSellOfferETH(
            _seller,
            _buyer,
            _tokenId,
            _deadline,
            _price
        );
        require(
            _price == msg.value,
            "ERC721Buyable: Not enought ETH to buy token"
        );
        require(
            SignatureChecker.isValidSignatureNow(
                _seller,
                digest,
                _sellerSignature
            ),
            "ERC721Buyable: Invalid signature"
        );
        require(
            block.timestamp < _deadline,
            "ERC721Buyable: Signed transaction expired"
        );
        nonces[_seller][_tokenId]++;
        if (_buyer == address(0)) {
            _buyer = msg.sender;
        }
        uint256 tax = (_price * saleTax) / saleTaxDenumerator;
        if (tax > 0) {
            payable(treasury).transfer(tax);
        }

        payable(_seller).transfer(_price - tax);
        _transfer(_seller, _buyer, _tokenId);

        emit SellOfferAcceptedETH(_seller, _buyer, _tokenId, _price);
    }

    function _hashSellOfferETH(
        address _from,
        address _to,
        uint256 _tokenId,
        uint256 _deadline,
        uint256 _price
    ) internal view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "SellOfferETH(address from,address to,uint256 tokenId,uint256 nonce,uint256 deadline,uint256 price)"
                    ),
                    _from,
                    _to,
                    _tokenId,
                    nonces[_from][_tokenId],
                    _deadline,
                    _price
                )
            )
        );
    }

    function buyAcceptingSellOfferWETH(
        address _seller,
        uint256 _tokenId,
        uint256 nonce,
        uint256 _deadline,
        uint256 _price,
        bytes memory _sellerSignature
    ) external {
        bytes32 digest = _hashSellOfferWETH(
            _seller,
            _tokenId,
            _deadline,
            _price
        );
        require(
            SignatureChecker.isValidSignatureNow(
                _seller,
                digest,
                _sellerSignature
            ),
            "ERC721Buyable: Invalid signature"
        );
        require(
            block.timestamp < _deadline,
            "ERC721Buyable: signed transaction expired"
        );
        nonces[_seller][_tokenId]++;
        uint256 tax = (_price * saleTax) / saleTaxDenumerator;
        if (tax > 0) {
            bool _success = paymentToken.transferFrom(_msgSender(), treasury, tax);
            require(_success, "ERC721Buyable: transfer failed");
        }
        bool _success = paymentToken.transferFrom(_msgSender(), _seller, _price - tax);
        require(_success, "ERC721Buyable: transfer failed");
        _transfer(_seller, _msgSender(), _tokenId);

        emit SellOfferAcceptedWETH(_seller, _msgSender(), _tokenId, _price);
    }

    function _hashSellOfferWETH(
        address _from,
        uint256 _tokenId,
        uint256 _deadline,
        uint256 _price
    ) internal view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "SellOfferWETH(address from,uint256 tokenId,uint256 nonce,uint256 deadline,uint256 price)"
                    ),
                    _from,
                    _tokenId,
                    nonces[_from][_tokenId],
                    _deadline,
                    _price
                )
            )
        );
    }

    function sellAcceptingBuyOfferWETH(
        address _buyer,
        uint256 _tokenId,
        uint256 nonce,
        uint256 _deadline,
        uint256 _price,
        bytes memory _sellerSignature
    ) external {
        bytes32 digest = _hashBuyOfferWETH(_buyer, _tokenId, _deadline, _price);
        require(
            _buyer.isValidSignatureNow(digest, _sellerSignature),
            "ERC721Buyable: Invalid signature"
        );
        require(
            block.timestamp < _deadline,
            "ERC721Buyable: signed transaction expired"
        );
        nonces[_buyer][_tokenId]++;
        uint256 tax = (_price * saleTax) / saleTaxDenumerator;
        if (tax > 0) {
            bool _success = paymentToken.transferFrom(_buyer, treasury, tax);
            require(_success, "ERC721Buyable: transfer failed");
        }
        bool _success = paymentToken.transferFrom(_buyer, _msgSender(), _price - tax);
        require(_success, "ERC721Buyable: transfer failed");
        _transfer(_msgSender(), _buyer, _tokenId);

        emit BuyOfferAcceptedWETH(_msgSender(), _buyer, _tokenId, _price);
    }

    function _hashBuyOfferWETH(
        address _to,
        uint256 _tokenId,
        uint256 _deadline,
        uint256 _price
    ) internal view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "BuyOfferWETH(address to,uint256 tokenId,uint256 nonce,uint256 deadline,uint256 price)"
                    ),
                    _to,
                    _tokenId,
                    nonces[_to][_tokenId],
                    _deadline,
                    _price
                )
            )
        );
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        } else if (error == RecoverError.InvalidSignatureV) {
            revert("ECDSA: invalid signature 'v' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        // Check the signature length
        // - case 65: r,s,v signature (standard)
        // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098) _Available since v4.1._
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else if (signature.length == 64) {
            bytes32 r;
            bytes32 vs;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }
            return tryRecover(hash, r, vs);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address, RecoverError) {
        bytes32 s;
        uint8 v;
        assembly {
            s := and(vs, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
            v := add(shr(255, vs), 27)
        }
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }
        if (v != 27 && v != 28) {
            return (address(0), RecoverError.InvalidSignatureV);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./ECDSA.sol";

/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding specified in the EIP is very generic, and such a generic implementation in Solidity is not feasible,
 * thus this contract does not implement the encoding itself. Protocols need to implement the type-specific encoding
 * they need in their contracts using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP 712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
 * scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA
 * ({_hashTypedDataV4}).
 *
 * The implementation of the domain separator was designed to be as efficient as possible while still properly updating
 * the chain id to protect against replay attacks on an eventual fork of the chain.
 *
 * NOTE: This contract implements the version of the encoding known as "v4", as implemented by the JSON RPC method
 * https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].
 *
 * _Available since v3.4._
 */
abstract contract EIP712 {
    /* solhint-disable var-name-mixedcase */
    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;

    /* solhint-enable var-name-mixedcase */

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    constructor(string memory name, string memory version) {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(typeHash, hashedName, hashedVersion);
        _TYPE_HASH = typeHash;
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
        }
    }

    function _buildDomainSeparator(
        bytes32 typeHash,
        bytes32 nameHash,
        bytes32 versionHash
    ) private view returns (bytes32) {
        return keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(this)));
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./ECDSA.sol";
import "../Address.sol";
import "../../interfaces/IERC1271.sol";

/**
 * @dev Signature verification helper: Provide a single mechanism to verify both private-key (EOA) ECDSA signature and
 * ERC1271 contract sigantures. Using this instead of ECDSA.recover in your contract will make them compatible with
 * smart contract wallets such as Argent and Gnosis.
 *
 * Note: unlike ECDSA signatures, contract signature's are revocable, and the outcome of this function can thus change
 * through time. It could return true at block N and false at block N+1 (or the opposite).
 *
 * _Available since v4.1._
 */
library SignatureChecker {
    function isValidSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
        if (error == ECDSA.RecoverError.NoError && recovered == signer) {
            return true;
        }

        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
        );
        return (success && result.length == 32 && abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector);
    }
}

// SPDX-License-Identifier: NONLICENSED
pragma solidity ^0.8.6;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "../interfaces/IWyvernProxyRegistry.sol";


abstract contract ERC721Tradable is ERC721, Ownable {
    address internal proxyRegistry;

    /**
     * Override isApprovedForAll to whitelist user's OpenSea proxy accounts to enable gas-less listings.
     */
    function isApprovedForAll(address _owner, address _operator)
        override
        public
        view
        returns (bool)
    {
        // Whitelist OpenSea proxy contract for easy trading.
        if (address(IWyvernProxyRegistry(proxyRegistry).proxies(_owner)) == _operator) {
            return true;
        }

        return super.isApprovedForAll(_owner, _operator);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and make it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCall(target, data, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC1271 standard signature validation method for
 * contracts as defined in https://eips.ethereum.org/EIPS/eip-1271[ERC-1271].
 *
 * _Available since v4.1._
 */
interface IERC1271 {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param hash      Hash of the data to be signed
     * @param signature Signature byte array associated with _data
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IERC721.sol";
import "./IERC721Receiver.sol";
import "./extensions/IERC721Metadata.sol";
import "../../utils/Address.sol";
import "../../utils/Context.sol";
import "../../utils/Strings.sol";
import "../../utils/introspection/ERC165.sol";

/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Mapping from token ID to owner address
    mapping(uint256 => address) private _owners;

    // Mapping owner address to token count
    mapping(address => uint256) private _balances;

    // Mapping from token ID to approved address
    mapping(uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overriden in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `_data` is additional data, it has no specified format and it is sent in call to `to`.
     *
     * This internal function is equivalent to {safeTransferFrom}, and can be used to e.g.
     * implement alternative mechanisms to perform token transfer, such as signature-based.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    /**
     * @dev Safely mints `tokenId` and transfers it to `to`.
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    /**
     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is
     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.
     */
    function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {Transfer} event.
     */
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }

    /**
     * @dev Destroys `tokenId`.
     * The approval is cleared when the token is burned.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     *
     * Emits a {Transfer} event.
     */
    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);

        // Clear approvals
        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }

    /**
     * @dev Transfers `tokenId` from `from` to `to`.
     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     *
     * Emits a {Transfer} event.
     */
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits a {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

interface IOwnableDelegateProxy {}

abstract contract IWyvernProxyRegistry {
    /* Authenticated proxies by user. */
    mapping(address => IOwnableDelegateProxy) public proxies;
    function registerProxy() public virtual returns (IOwnableDelegateProxy proxy);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../IERC721.sol";

/**
 * @title ERC-721 Non-Fungible Token Standard, optional metadata extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Metadata is IERC721 {
    /**
     * @dev Returns the token collection name.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the token collection symbol.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.
     */
    function tokenURI(uint256 tokenId) external view returns (string memory);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IERC165.sol";

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 *
 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.6;

interface IWithdrawable {
    function pendingWithdrawal() external view returns (uint);
    function withdraw(uint amount) external;
    function withdrawAll() external;
}
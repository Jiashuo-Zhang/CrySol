// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import "../IToken.sol";

contract WAncientTLS is Ownable {
    uint256 public tokenId;

    bool public isPrivateTwoMint = true;
    bool public isPublicMint;

    //PRICES
    uint256 public mintPriceBundleEth = 0.17 ether; //0.17 ether;
    //TBD
    uint256 public mintPriceBundleWrld = 3000 ether;

    bytes32 public whitelistMerkleRoot;

    address public foundersWallet;

    IToken public WRLD_TOKEN;

    event BundleMintEth(address indexed player, uint256 indexed tokenId, uint256 numberOfTokens);
    event BundleMintWrld(address indexed player, uint256 indexed tokenId, uint256 numberOfTokens);

    constructor(){
        foundersWallet = 0x02367e1ed0294AF91E459463b495C8F8F855fBb8;
        WRLD_TOKEN = IToken(0xD5d86FC8d5C0Ea1aC1Ac5Dfab6E529c9967a45E9);
        whitelistMerkleRoot = 0x23b56d3d5fdb3794dbde2d8b4ddb588f3d3a26564ee14a099fa2dbaa303f51fa;
    }
    

    function setFoundersWallet(address newFoundersWallet) external onlyOwner{
        foundersWallet = newFoundersWallet;
    }

    //CONTROL FUNCTIONS
    function updateWhitelistMerkleRoot(bytes32 _newMerkleRoot)
        external
        onlyOwner
    {
        whitelistMerkleRoot = _newMerkleRoot;
    }
    
    function setPrice(uint256 mintPriceBundleEth_, uint256 mintPriceBundleWrld_) external onlyOwner{
        mintPriceBundleEth = mintPriceBundleEth_;
        mintPriceBundleWrld = mintPriceBundleWrld_;
    }

    function setPrivateTwoMint(bool isPrivateMint_) external onlyOwner{
        isPrivateTwoMint = isPrivateMint_;
    }

    function setPublicMint(bool isPublicMint_) external onlyOwner{
        isPublicMint = isPublicMint_;
    }

    modifier onlyMinter(address player, uint256 _numberOfTokens,  bytes32[] calldata merkleProof){
        require(isPrivateTwoMint || isPublicMint, "Mint not open");
        require(_numberOfTokens <= 3, "max 3 blds");

        if(!isPublicMint){
            bool isWhitelisted = MerkleProof.verify(
                merkleProof, //routeProof
                whitelistMerkleRoot, //root
                keccak256(abi.encodePacked(player)/* leaf */)
            );
            require(isWhitelisted, "invalid-proof");
        }
        _;
    }

    function mint(address player, uint256 _numberOfTokens,  bytes32[] calldata merkleProof) external payable onlyMinter(player, _numberOfTokens, merkleProof){

        require(msg.value >= mintPriceBundleEth * _numberOfTokens, "inc-pol-val");

        
        emit BundleMintEth(player, tokenId, _numberOfTokens);
        tokenId += _numberOfTokens;
        
    }

    function mintWrld(address player, uint256 _numberOfTokens,  bytes32[] calldata merkleProof) external payable onlyMinter(player, _numberOfTokens, merkleProof){
        require(mintPriceBundleWrld * _numberOfTokens <= WRLD_TOKEN.balanceOf(player), "low-balance-wrld");
        require(mintPriceBundleWrld * _numberOfTokens <= WRLD_TOKEN.allowance(player, address(this)), "low-allowance-wrld");

        
        emit BundleMintWrld(player, tokenId, _numberOfTokens);
        tokenId += _numberOfTokens;
        
        WRLD_TOKEN.transferFrom(player, foundersWallet, mintPriceBundleWrld * _numberOfTokens);
    }

    function withdraw() external onlyOwner {
        uint256 _balance = address(this).balance;
        payable(foundersWallet).transfer(_balance);
    }

}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf(address owner) external view returns(uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address, address, uint256) external;
    function allowance(address owner, address spender) external view returns(uint256);
    function approve(address spender, uint256 amount) external returns(bool);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Trees proofs.
 *
 * The proofs can be generated using the JavaScript library
 * https://github.com/miguelmota/merkletreejs[merkletreejs].
 * Note: the hashing algorithm should be keccak256 and pair sorting should be enabled.
 *
 * See `test/utils/cryptography/MerkleProof.test.js` for some examples.
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merklee tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = _efficientHash(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = _efficientHash(proofElement, computedHash);
            }
        }
        return computedHash;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

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
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

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
        _transferOwnership(_msgSender());
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
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
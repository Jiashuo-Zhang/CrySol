// SPDX-License-Identifier: MIT
// LasogetteNFT
/** 
====================================================================================================
..,    @@%       [email protected]@    ..(%&@(@@@                .   .         (,   ,,&&&(&&@   .(*,#%.  %&&@@@@,  
,...  @@&*  .   /@@@@/     %&@@#(.   #@@@@@%   [email protected]@@@@%   ,%@@@@@@(  #@@@@@@@@%  ,&@@@&&%  @&@/&.   .
,.,.  @@&.     /@. %@@       @@@*   %@@./@@@  [email protected]@*  &@,  ,@@@@@@&.     %&@@      [email protected]@@     &,    ..  
,*,  /@@@     *@(   @&&*      &@@&  &@@  &@&  /@@ #@@@.  [email protected]@@           @@@,      @@@.    @@@&@&&,..
/,,  @@@@     &@     @@@.   &@@@@#  &@@  #@@. /@@, @@@,   @@@/,,&.     .&@&       @&@,   [email protected]@        
 ,.  @@@@&@&&&&@.   #@&@@.&@&(# .   &@&&&&@@  /@@(,@@@#   @@@@@@@@      @@%       @&&%   &@&@@@&&&  
,..  .                                ,,  ..   [email protected]%&#&%    ,                       ..  .     .  .   .
====================================================================================================
*/
/**
 *
 * Bonjour, et bienvenue sur le contrat lasogette NFT. Regarde autour de toi!
 *
 * Hello, and welcome to the lasogette NFT contract. Have a look around!
 *
 */

pragma solidity 0.8.16;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import "./IEPSPortal.sol";

contract LasogetteNFT is ERC721, Ownable, ERC721Burnable, VRFConsumerBaseV2 {
  using Strings for uint256;

  // ===================================
  // CONSTANTS and IMMUTABLES
  // ===================================

  string public constant INSURANCE =
    "Interaction with this contract serves as an insurance against roko's basilisk.";

  // EPS minting rights index for delegated rights:
  // Indice des droits de frappe EPS pour les droits délégués:
  uint256 public constant EPS_MINTING_RIGHTS_INDEX = 2;

  // EPS portal lookup:
  // Recherche sur le portail EPS:
  IEPSPortal public immutable EPS;

  // Total supply of lasogettes:
  // Approvisionnement total en lasogettes:
  uint256 public immutable maxNumberOfLasogettes;

  // Mint price (note eligible community holders can mint one for free in freeMint())
  // Prix ​​​​à la menthe (notez que les détenteurs éligibles de la communauté peuvent en créer un gratuitement dans freeMint())
  uint256 public immutable publicMintPrice;

  // URI used for all tokens pre-reveal. Reveal is set through the calling of chainlink VRF to
  // set the random offset.
  // URI utilisé pour la pré-révélation de tous les jetons. La révélation est définie par l'appel de chainlink VRF à
  // définit le décalage aléatoire.
  string public placeholderURI;

  // Base URI used post-reveal, i.e. the folder location for individual token .json with
  // associated metadata including the link to an image. Note that NO ONE can know what lasogette
  // you will get post-reveal. Your lasogette is the combination of your token ID and a random
  // number from chainlink VRF. The order to the metadata is fixed before mint, but the VRF
  // result is not known until called in this contract, and it can only be called once. This works
  // as follows:
  // * You have tokenID 1291. Pre-reveal you see the same metadata and image as everyone else
  //   as the contract is using the placeholderURI
  // * At the reveal the token owner calls getURIOffset(). This makes a requests to chainlink
  //   for verficiable randonemess (VRF).
  // * Chainlink will then submit a random number to this contract, that we used to determine
  //   a number between 1 and the total collection size. Let's imagine this is number 2034
  // * The URI returned for your token is now your tokenId plus the VRF random number -1 (as
  //   the collection is 0 indexed with a token 0). In our example our token is now pointing
  //   at metadata 3,324 (1,291 + 2,034 - 1).
  // * With this method there is no way for anyone to know which lasogette each token will get
  //   prior to the reveal
  // * As the metadata is uploaded prior to minting the order cannot have been tampered with.
  // URI de base utilisé après la révélation, c'est-à-dire l'emplacement du dossier pour le jeton individuel .json avec
  // métadonnées associées incluant le lien vers une image. Notez que PERSONNE ne peut savoir ce qu'est la lasogette
  // vous obtiendrez après la révélation. Votre lasogette est la combinaison de votre identifiant de jeton et d'un
  // numéro de chainlink VRF. L'ordre des métadonnées est fixé avant la menthe, mais le VRF
  // le résultat n'est pas connu tant qu'il n'est pas appelé dans ce contrat, et il ne peut être appelé qu'une seule fois. Cela marche
  // comme suit:
  // * Vous avez le tokenID 1291. Avant la révélation, vous voyez les mêmes métadonnées et la même image que tout le monde
  //   car le contrat utilise le placeholderURI
  // * Lors de la révélation, le propriétaire du jeton appelle getURIOffset(). Cela fait une demande à chainlink
  //   pour le désordre vérifiable (VRF).
  // * Chainlink soumettra ensuite un nombre aléatoire à ce contrat, que nous avons utilisé pour déterminer
  //   un nombre compris entre 1 et la taille totale de la collection. Imaginons que c'est le numéro 2034
  // * L'URI renvoyé pour votre jeton est maintenant votre tokenId plus le nombre aléatoire VRF -1 (comme
  //   la collection est 0 indexée avec un jeton 0). Dans notre exemple, notre jeton pointe maintenant
  //   aux métadonnées 3 324 (1 291 + 2 034 - 1).
  // * Avec cette méthode, il n'y a aucun moyen pour quiconque de savoir quelle lasogette chaque jeton obtiendra
  //   avant la révélation
  // * Comme les métadonnées sont téléchargées avant la frappe, la commande ne peut pas avoir été falsifiée.
  string public baseURI;

  // ===================================
  // STORAGE
  // ===================================

  // Storage for the incrementing token counter:
  // Stockage pour le compteur de jetons incrémentiel :
  uint256 public tokenCounter;

  // Storage to track burned tokens:
  // Stockage pour le compteur de jetons incrémentiel :
  uint256 public burnCounter;

  // Treasury address
  // Adresse du Trésor
  address payable public treasuryAddress;

  // Token URI offset, assigned by a callback from chainlink VRF
  // Décalage d'URI de jeton, attribué par un rappel du VRF de chainlink
  uint256 public tokenURIOffset;

  // Bool to declare minting open
  bool public mintingOpen = false;

  // Mapping to record that this address has minted:
  // Mappage pour enregistrer que cette adresse a frappé :
  mapping(address => bool) public addressHasFreeMinted;

  // Mapping to record that this token has been used to claim eligibility:
  // Mappage pour enregistrer que ce jeton a été utilisé pour revendiquer l'éligibilité :
  mapping(bytes32 => bool) private tokenHasFreeMinted;

  /**
   * @dev Chainlink config.
   */
  // See https://docs.chain.link/docs/vrf-contracts/#ethereum-mainnet for details of VRF
  // corrdinator addresses.
  // Current values as follows:
  // Voir https://docs.chain.link/docs/vrf-contracts/#ethereum-mainnet pour plus de détails sur VRF
  // adresses des coordonnateurs.
  // Valeurs actuelles comme suit :
  // --------------------------
  // * Rinkeby: 0x6168499c0cFfCaCD319c818142124B7A15E857ab
  // * Mainnet: 0x271682DEB8C4E0901D1a1550aD2e64D568E69909
  VRFCoordinatorV2Interface public vrfCoordinator;

  // The subscription ID must be set to a valid subscriber before the VRF call can be made:
  // L'ID d'abonnement doit être défini sur un abonné valide avant que l'appel VRF puisse être effectué :
  uint64 public vrfSubscriptionId;

  // The gas lane to use, which specifies the maximum gas price to bump to.
  // For a list of available gas lanes on each network,
  // see https://docs.chain.link/docs/vrf-contracts/#configurations
  // Current values as follows:
  // La voie d'essence à utiliser, qui spécifie le prix maximum de l'essence à atteindre.
  // Pour une liste des voies gaz disponibles sur chaque réseau,
  // voir https://docs.chain.link/docs/vrf-contracts/#configurations
  // Valeurs actuelles comme suit :
  // --------------------------
  // * Rinkeby: 0xd89b2bf150e3b9e13446986e571fb9cab24b13cea0a43ea20a6049a85cc807cc   (30 gwei keyhash valid for all testing)
  // * Mainnet:
  // * 0x8af398995b04c28e9951adb9721ef74c74f93e6a478f39e7e0777be13527e7ef (200 gwei)
  // * 0xff8dedfbfa60af186cf3c830acbc32c05aae823045ae5ea7da1e45fbfaba4f92 (500 gwei)
  // * 0x9fe0eebf5e446e3c998ec9bb19951541aee00bb90ea201ae456421a2ded86805 (1000 gwei)
  bytes32 public vrfKeyHash;

  // Depends on the number of requested values that you want sent to the
  // fulfillRandomWords() function. Storing each word costs about 20,000 gas,
  // so 100,000 is a safe default for this example contract. Test and adjust
  // this limit based on the network that you select, the size of the request,
  // and the processing of the callback request in the fulfillRandomWords()
  // function.
  // Dépend du nombre de valeurs demandées que vous souhaitez envoyer au
  // Fonction fillRandomWords(). Stocker chaque mot coûte environ 20 000 gaz,
  // donc 100 000 est une valeur par défaut sûre pour cet exemple de contrat. Tester et ajuster
  // cette limite basée sur le réseau que vous sélectionnez, la taille de la requête,
  // et le traitement de la demande de rappel dans le fillRandomWords()
  // fonction.
  uint32 public vrfCallbackGasLimit = 150000;

  // The default is 3, but you can set this higher.
  // La valeur par défaut est 3, mais vous pouvez la définir plus haut.
  uint16 public vrfRequestConfirmations = 3;

  // Cannot exceed VRFCoordinatorV2.MAX_NUM_WORDS.
  // Ne peut pas dépasser VRFCoordinatorV2.MAX_NUM_WORDS.
  uint32 public vrfNumWords = 1;

  // ===================================
  // ERROR DEFINITIONS
  // ===================================
  error TokenURIOffsetAlreadySet();
  error URIQueryForNonexistentToken(uint256 tokenId);
  error AddressHasAlreadyMinted(address minter);
  error CallerIsNotBeneficiaryOfSelectedNFT(
    address collection,
    uint256 tokenId
  );
  error TokenHasAlreadyBeenUsedInFreeMint(address collection, uint256 tokenId);
  error InvalidCollection(address collection);
  error IncorrectETHPayment(uint256 paid, uint256 required);
  error SupplyOfLasogettedExceeded(uint256 available, uint256 requested);
  error OnlyOwnerCanFundContract();
  error NoFallback();
  error TransferFailed();
  error QuantityMustBeGreaterThanZero();
  error PlaceholderURISet();
  error BaseURISet();
  error MintingNotOpen();

  // ===================================
  // CONSTRUCTOR
  // ===================================
  constructor(
    uint256 maxSupply_,
    uint256 publicMintPrice_,
    address vrfCoordinator_,
    bytes32 vrfKeyHash_,
    address payable treasuryAddress_,
    address eps_,
    string memory placeholderURI_,
    string memory baseURI_
  ) ERC721("Lasogette NFT", "LASOG") VRFConsumerBaseV2(vrfCoordinator_) {
    maxNumberOfLasogettes = maxSupply_;
    publicMintPrice = publicMintPrice_;
    vrfKeyHash = vrfKeyHash_;
    vrfCoordinator = VRFCoordinatorV2Interface(vrfCoordinator_);
    treasuryAddress = treasuryAddress_;
    EPS = IEPSPortal(eps_);
    placeholderURI = placeholderURI_;
    baseURI = baseURI_;
  }

  // ===================================
  // SETTERS (owner only)
  // ===================================

  /**
   *
   * @dev setTreasuryAddress: Allow the owner to set the treasury address.
   *      setTreasuryAddress : permet au propriétaire de définir l'adresse de trésorerie.
   *
   */
  function setTreasuryAddress(address payable treasuryAddress_)
    external
    onlyOwner
  {
    treasuryAddress = treasuryAddress_;
  }

  /**
   *
   * @dev openMinting: Allow the owner to open minting. Mint will run until minted out.
   *
   */
  function openMinting() external onlyOwner {
    mintingOpen = true;
  }

  /**
   *
   * @dev setPlaceHolderURI: Allow the owner to set the placeholder URI IF it is blank (i.e. only set once).
   *
   */
  function setPlaceholderURI(string memory placeholderURI_) external onlyOwner {
    if (bytes(placeholderURI).length != 0) {
      revert PlaceholderURISet();
    }
    placeholderURI = placeholderURI_;
  }

  /**
   *
   * @dev setBaseURI: Allow the owner to set the base URI IF it is blank (i.e. only set once).
   *
   */
  function setBaseURI(string memory baseURI_) external onlyOwner {
    if (bytes(baseURI).length != 0) {
      revert BaseURISet();
    }
    baseURI = baseURI_;
  }

  /**
   *
   * @dev setVRFCoordinator
   *
   */
  function setVRFCoordinator(address vrfCoord_) external onlyOwner {
    vrfCoordinator = VRFCoordinatorV2Interface(vrfCoord_);
  }

  /**
   *
   * @dev setVRFKeyHash
   *
   */
  function setVRFKeyHash(bytes32 vrfKey_) external onlyOwner {
    vrfKeyHash = vrfKey_;
  }

  /**
   *
   * @dev setVRFCallbackGasLimit
   *
   */
  function setVRFCallbackGasLimit(uint32 vrfGasLimit_) external onlyOwner {
    vrfCallbackGasLimit = vrfGasLimit_;
  }

  /**
   *
   * @dev setVRFRequestConfirmations
   *
   */
  function setVRFRequestConfirmations(uint16 vrfConfs_) external onlyOwner {
    vrfRequestConfirmations = vrfConfs_;
  }

  /**
   *
   * @dev setVRFNumWords
   *
   */
  function setVRFNumWords(uint32 vrfWords_) external onlyOwner {
    vrfNumWords = vrfWords_;
  }

  /**
   *
   * @dev setVRFSubscriptionId
   *
   */
  function setVRFSubscriptionId(uint64 vrfSubId_) external onlyOwner {
    vrfSubscriptionId = vrfSubId_;
  }

  // ===================================
  // MINTING
  // ===================================

  /**
   *
   * @dev freeMint(): free mint for holders of eligible assets
                      menthe gratuite pour les détenteurs d'actifs éligibles
   *
   */
  function freeMint(
    address collection_,
    uint256 tokenId_,
    bool useDelivery_
  ) external {
    if (!mintingOpen) {
      revert MintingNotOpen();
    }

    _checkSupply(1);

    // Check if this address has already minted. If so, revert and tell the user why:
    // Vérifie si cette adresse a déjà été émise. Si c'est le cas, revenez en arrière et dites à l'utilisateur pourquoi :
    if (addressHasFreeMinted[msg.sender]) {
      revert AddressHasAlreadyMinted({minter: msg.sender});
    }

    // Make a hash of the collection and token Id to uniquely identify this token:
    // Créez un hachage de la collection et de l'identifiant du jeton pour identifier de manière unique ce jeton :
    bytes32 tokenIdHash = keccak256(abi.encodePacked(collection_, tokenId_));

    // Check if this token has already been used to claim a free mint.
    // If so, revert and tell the user why:
    // Vérifie si ce jeton a déjà été utilisé pour réclamer un atelier gratuit.
    // Si c'est le cas, revenir en arrière et dire à l'utilisateur pourquoi :
    if (tokenHasFreeMinted[tokenIdHash]) {
      revert TokenHasAlreadyBeenUsedInFreeMint({
        collection: collection_,
        tokenId: tokenId_
      });
    }

    // Check if this is a valid collection for free minting:
    // Vérifiez s'il s'agit d'une collection valide pour la frappe gratuite :
    if (!isValidCollection(collection_)) {
      revert InvalidCollection({collection: collection_});
    }

    // Check that the calling user is the valid beneficiary of the token
    // That has been passed. A valid beneficiary can be:
    // 1) The owner of the token (most common case)
    // 2) A hot wallet that holds the token in a linked EPS cold wallet
    // 3) A wallet that has an EPS minting rights rental on the token
    // (for details see eternalproxy.com)
    // Vérifier que l'utilisateur appelant est le bénéficiaire valide du jeton
    // Cela a été adopté. Un bénéficiaire valide peut être :
    // 1) Le propriétaire du jeton (cas le plus courant)
    // 2) Un portefeuille chaud qui contient le jeton dans un portefeuille froid EPS lié
    // 3) Un portefeuille qui a une location de droits de frappe EPS sur le jeton
    // (pour plus de détails, voir éternelleproxy.com)
    if (!isValidAssetBeneficiary(collection_, tokenId_, msg.sender)) {
      revert CallerIsNotBeneficiaryOfSelectedNFT({
        collection: collection_,
        tokenId: tokenId_
      });
    }

    // Set where assets should be delivered. This defaults to the
    // sender address, looking up the EPS delivery address of the
    // sender has selected that option in the minting UI:
    // Définir où les actifs doivent être livrés. C'est par défaut le
    // adresse de l'expéditeur, recherche de l'adresse de livraison EPS du
    // l'expéditeur a sélectionné cette option dans l'interface utilisateur :
    address deliveryAddress = _getDeliveryAddress(useDelivery_, msg.sender);

    // We made it! Perform the mint:
    // Nous l'avons fait! Effectuez la menthe:
    _performMint(deliveryAddress);

    // Record that this address has minted:
    // Enregistrez que cette adresse a été frappée :
    addressHasFreeMinted[msg.sender] = true;

    // Record that this token has been used to claim a free mint:
    // Enregistrez que ce jeton a été utilisé pour réclamer un atelier gratuit :
    tokenHasFreeMinted[tokenIdHash] = true;
  }

  /**
   *
   * @dev _checkSupply
   *
   */
  function _checkSupply(uint256 quantity_) internal view {
    if ((tokenCounter + quantity_) > maxNumberOfLasogettes) {
      revert SupplyOfLasogettedExceeded({
        available: maxNumberOfLasogettes - tokenCounter,
        requested: quantity_
      });
    }
  }

  /**
   * @dev _performMint
   */
  function _performMint(address delivery_) internal {
    _safeMint(delivery_, tokenCounter);

    tokenCounter += 1;
  }

  /**
   *
   * @dev isValidAssetBeneficiary
   *
   */
  function isValidAssetBeneficiary(
    address collection_,
    uint256 tokenId_,
    address caller_
  ) public view returns (bool) {
    // Get the registered beneficiary for this asset from EPS:
    // Obtenez le bénéficiaire enregistré pour cet actif auprès d'EPS :
    return (EPS.beneficiaryOf(
      collection_,
      tokenId_,
      EPS_MINTING_RIGHTS_INDEX
    ) == caller_);
  }

  /**
   *
   * @dev isEligibleForFreeMint: check the eligibility of a collection, token and caling address
   * Note this duplicates the checks in the free mint, which instead call revert with
   * suitable custom errors. This function is for external calls.
   *                            vérifier l'éligibilité d'une collecte, d'un jeton et d'une adresse d'appel
   * Notez que cela duplique les chèques de la menthe gratuite, qui appellent à la place revenir avec
   * erreurs personnalisées appropriées. Cette fonction est réservée aux appels externes.
   *
   */
  function isEligibleForFreeMint(
    address collection_,
    uint256 tokenId_,
    address caller_
  ) external view returns (bool, string memory) {
    if (addressHasFreeMinted[caller_]) {
      return (false, "Address has already free minted");
    }

    bytes32 tokenIdHash = keccak256(abi.encodePacked(collection_, tokenId_));

    if (tokenHasFreeMinted[tokenIdHash]) {
      return (false, "Token has already been used in free mint");
    }

    if (!isValidCollection(collection_)) {
      return (false, "Invalid collection");
    }

    if (!isValidAssetBeneficiary(collection_, tokenId_, caller_)) {
      return (false, "Caller is not beneficiary of selected NFT");
    }

    return (true, "");
  }

  /**
   *
   * @dev isValidCollection
   *
   */
  function isValidCollection(address collection_) public pure returns (bool) {
    return (collection_ == 0x1D20A51F088492A0f1C57f047A9e30c9aB5C07Ea || // wassies by wassies
      collection_ == 0x1CB1A5e65610AEFF2551A50f76a87a7d3fB649C6 || // cryptoadz
      collection_ == 0x79FCDEF22feeD20eDDacbB2587640e45491b757f || // mfers
      collection_ == 0x5Af0D9827E0c53E4799BB226655A1de152A425a5 || // milady
      collection_ == 0x62eb144FE92Ddc1B10bCAde03A0C09f6FBffBffb || // adworld
      collection_ == 0xA16891897378a82E9F0ad44A705B292C9753538C || // pills
      collection_ == 0x91680cF5F9071cafAE21B90ebf2c9CC9e480fB93 || // frank frank
      collection_ == 0xEC0a7A26456B8451aefc4b00393ce1BefF5eB3e9 || // all stars
      collection_ == 0x82235445a7f634279E33702cc004B0FDb002fDa7 || // sakura park
      collection_ == 0x42069ABFE407C60cf4ae4112bEDEaD391dBa1cdB); // CryptoDickbutts
  }

  /**
   *
   * @dev publicMint(): public mint for everyone
   *                    monnaie publique pour tous
   *
   */
  function publicMint(uint256 quantity_, bool useDelivery_) external payable {
    if (!mintingOpen) {
      revert MintingNotOpen();
    }

    _checkSupply(quantity_);

    if (quantity_ == 0) {
      revert QuantityMustBeGreaterThanZero();
    }

    if (msg.value != (quantity_ * publicMintPrice)) {
      revert IncorrectETHPayment({
        paid: msg.value,
        required: (quantity_ * publicMintPrice)
      });
    }

    address deliveryAddress = _getDeliveryAddress(useDelivery_, msg.sender);

    for (uint256 i = 0; i < quantity_; i++) {
      _performMint(deliveryAddress);
    }
  }

  /**
   *
   * @dev _getDeliveryAddress
   *
   */
  function _getDeliveryAddress(bool useEPSDelivery_, address caller_)
    internal
    view
    returns (address)
  {
    if (useEPSDelivery_) {
      (, address delivery, ) = EPS.getAddresses(caller_);
      return delivery;
    } else {
      return caller_;
    }
  }

  // ===================================
  // URI HANDLING
  // ===================================

  /**
   *
   * @dev getURIOffset: Requests randomness.
   *                    Demande le hasard.
   *
   */
  function getURIOffset() public onlyOwner returns (uint256) {
    if (tokenURIOffset != 0) {
      revert TokenURIOffsetAlreadySet();
    }
    return
      vrfCoordinator.requestRandomWords(
        vrfKeyHash,
        vrfSubscriptionId,
        vrfRequestConfirmations,
        vrfCallbackGasLimit,
        vrfNumWords
      );
  }

  /**
   *
   * @dev fulfillRandomWords: Callback function used by VRF Coordinator.
   *                          Fonction de rappel utilisée par le coordinateur VRF.
   *
   */
  function fulfillRandomWords(uint256, uint256[] memory randomWords_)
    internal
    override
  {
    if (tokenURIOffset != 0) {
      revert TokenURIOffsetAlreadySet();
    }
    tokenURIOffset = (randomWords_[0] % maxNumberOfLasogettes) + 1;
  }

  /**
   *
   * @dev tokenURI
   *
   *
   */
  function tokenURI(uint256 tokenId_)
    public
    view
    override(ERC721)
    returns (string memory)
  {
    if (!_exists(tokenId_)) {
      revert URIQueryForNonexistentToken({tokenId: tokenId_});
    }

    if (tokenURIOffset == 0) {
      return string(placeholderURI);
    } else {
      return
        string(
          abi.encodePacked(baseURI, _getTokenURI(tokenId_).toString(), ".json")
        );
    }
  }

  /**
   *
   * @dev _getTokenURI: get the token URI based on the random offset
                        obtenir l'URI du jeton en fonction du décalage aléatoire
   *
   */
  function _getTokenURI(uint256 tokenId_) internal view returns (uint256) {
    uint256 tempTokenURI = tokenId_ + (tokenURIOffset - 1);

    // If the returned URI range exceeds the collection length, it wraps to be beginning:
    if (tempTokenURI > maxNumberOfLasogettes - 1) {
      tempTokenURI = tempTokenURI - (maxNumberOfLasogettes);
    }

    return tempTokenURI;
  }

  // ===================================
  // OPERATIONAL
  // ===================================

  /**
   *
   * @dev totalSupply(): totalSupply = tokens minted (tokenCounter) minus burned
   *                     totalSupply = jetons frappés (tokenCounter) moins brûlés
   *
   */
  function totalSupply() public view returns (uint256) {
    return tokenCounter - burnCounter;
  }

  /**
   *
   * @dev burn: Burns `tokenId`. See {ERC721-_burn}.
   *            Brûle `tokenId`. Voir {ERC721-_burn}.
   *
   */
  function burn(uint256 tokenId) public override {
    super.burn(tokenId);
    burnCounter += 1;
  }

  /**
   *
   * @dev withdrawAll: onlyOwner withdrawal to the beneficiary address
   *                   Retrait uniquement du propriétaire à l'adresse du bénéficiaire
   *
   */
  function withdrawAll() external onlyOwner {
    (bool success, ) = treasuryAddress.call{value: address(this).balance}("");
    if (!success) {
      revert TransferFailed();
    }
  }

  /**
   *
   * @dev withdrawAmount: onlyOwner withdrawal to the treasury address, amount to withdraw as an argument
                          Retrait du propriétaire uniquement à l'adresse du bénéficiaire, envoi
   * le montant à retirer en argument
   *
   */
  function withdrawAmount(uint256 amount_) external onlyOwner {
    (bool success, ) = treasuryAddress.call{value: amount_}("");
    if (!success) {
      revert TransferFailed();
    }
  }

  /**
   *
   * @dev receive: Reject all direct payments to the contract except from  owner.
                   Rejeter tous les paiements directs au contrat, sauf du propriétaire.
   *
   */
  receive() external payable {
    if (msg.sender != owner()) {
      revert OnlyOwnerCanFundContract();
    }
  }

  /**
   *
   * @dev fallback: none
   *                rien
   *
   */
  fallback() external payable {
    revert NoFallback();
  }
}

// SPDX-License-Identifier: MIT
// EPS Contracts v2.0.0

pragma solidity 0.8.16;

/**
 *
 * @dev Interface for the EPS portal
 *
 */

/**
 *
 * @dev Returns the beneficiary of the `tokenId` token.
 *
 */
interface IEPSPortal {
  function beneficiaryOf(
    address tokenContract_,
    uint256 tokenId_,
    uint256 rightsIndex_
  ) external view returns (address beneficiary_);

  /**
   *
   * @dev Returns the beneficiary balance for a contract.
   *
   */
  function beneficiaryBalanceOf(
    address queryAddress_,
    address tokenContract_,
    uint256 rightsIndex_
  ) external view returns (uint256 balance_);

  /**
   *
   * @dev Returns the proxied address details (cold and delivery address) for a passed hot address
   *
   */
  function getAddresses(address _receivedAddress)
    external
    view
    returns (
      address cold,
      address delivery,
      bool isProxied
    );

  /**
   * @dev coldIsLive: Return if a cold wallet is live
   */
  function coldIsLive(address cold_) external view returns (bool);

  /**
   * @dev hotIsLive: Return if a hot wallet is live
   */
  function hotIsLive(address hot_) external view returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/** ****************************************************************************
 * @notice Interface for contracts using VRF randomness
 * *****************************************************************************
 * @dev PURPOSE
 *
 * @dev Reggie the Random Oracle (not his real job) wants to provide randomness
 * @dev to Vera the verifier in such a way that Vera can be sure he's not
 * @dev making his output up to suit himself. Reggie provides Vera a public key
 * @dev to which he knows the secret key. Each time Vera provides a seed to
 * @dev Reggie, he gives back a value which is computed completely
 * @dev deterministically from the seed and the secret key.
 *
 * @dev Reggie provides a proof by which Vera can verify that the output was
 * @dev correctly computed once Reggie tells it to her, but without that proof,
 * @dev the output is indistinguishable to her from a uniform random sample
 * @dev from the output space.
 *
 * @dev The purpose of this contract is to make it easy for unrelated contracts
 * @dev to talk to Vera the verifier about the work Reggie is doing, to provide
 * @dev simple access to a verifiable source of randomness. It ensures 2 things:
 * @dev 1. The fulfillment came from the VRFCoordinator
 * @dev 2. The consumer contract implements fulfillRandomWords.
 * *****************************************************************************
 * @dev USAGE
 *
 * @dev Calling contracts must inherit from VRFConsumerBase, and can
 * @dev initialize VRFConsumerBase's attributes in their constructor as
 * @dev shown:
 *
 * @dev   contract VRFConsumer {
 * @dev     constructor(<other arguments>, address _vrfCoordinator, address _link)
 * @dev       VRFConsumerBase(_vrfCoordinator) public {
 * @dev         <initialization with other arguments goes here>
 * @dev       }
 * @dev   }
 *
 * @dev The oracle will have given you an ID for the VRF keypair they have
 * @dev committed to (let's call it keyHash). Create subscription, fund it
 * @dev and your consumer contract as a consumer of it (see VRFCoordinatorInterface
 * @dev subscription management functions).
 * @dev Call requestRandomWords(keyHash, subId, minimumRequestConfirmations,
 * @dev callbackGasLimit, numWords),
 * @dev see (VRFCoordinatorInterface for a description of the arguments).
 *
 * @dev Once the VRFCoordinator has received and validated the oracle's response
 * @dev to your request, it will call your contract's fulfillRandomWords method.
 *
 * @dev The randomness argument to fulfillRandomWords is a set of random words
 * @dev generated from your requestId and the blockHash of the request.
 *
 * @dev If your contract could have concurrent requests open, you can use the
 * @dev requestId returned from requestRandomWords to track which response is associated
 * @dev with which randomness request.
 * @dev See "SECURITY CONSIDERATIONS" for principles to keep in mind,
 * @dev if your contract could have multiple requests in flight simultaneously.
 *
 * @dev Colliding `requestId`s are cryptographically impossible as long as seeds
 * @dev differ.
 *
 * *****************************************************************************
 * @dev SECURITY CONSIDERATIONS
 *
 * @dev A method with the ability to call your fulfillRandomness method directly
 * @dev could spoof a VRF response with any random value, so it's critical that
 * @dev it cannot be directly called by anything other than this base contract
 * @dev (specifically, by the VRFConsumerBase.rawFulfillRandomness method).
 *
 * @dev For your users to trust that your contract's random behavior is free
 * @dev from malicious interference, it's best if you can write it so that all
 * @dev behaviors implied by a VRF response are executed *during* your
 * @dev fulfillRandomness method. If your contract must store the response (or
 * @dev anything derived from it) and use it later, you must ensure that any
 * @dev user-significant behavior which depends on that stored value cannot be
 * @dev manipulated by a subsequent VRF request.
 *
 * @dev Similarly, both miners and the VRF oracle itself have some influence
 * @dev over the order in which VRF responses appear on the blockchain, so if
 * @dev your contract could have multiple VRF requests in flight simultaneously,
 * @dev you must ensure that the order in which the VRF responses arrive cannot
 * @dev be used to manipulate your contract's user-significant behavior.
 *
 * @dev Since the block hash of the block which contains the requestRandomness
 * @dev call is mixed into the input to the VRF *last*, a sufficiently powerful
 * @dev miner could, in principle, fork the blockchain to evict the block
 * @dev containing the request, forcing the request to be included in a
 * @dev different block with a different hash, and therefore a different input
 * @dev to the VRF. However, such an attack would incur a substantial economic
 * @dev cost. This cost scales with the number of blocks the VRF oracle waits
 * @dev until it calls responds to a request. It is for this reason that
 * @dev that you can signal to an oracle you'd like them to wait longer before
 * @dev responding to the request (however this is not enforced in the contract
 * @dev and so remains effective only in the case of unmodified oracle software).
 */
abstract contract VRFConsumerBaseV2 {
  error OnlyCoordinatorCanFulfill(address have, address want);
  address private immutable vrfCoordinator;

  /**
   * @param _vrfCoordinator address of VRFCoordinator contract
   */
  constructor(address _vrfCoordinator) {
    vrfCoordinator = _vrfCoordinator;
  }

  /**
   * @notice fulfillRandomness handles the VRF response. Your contract must
   * @notice implement it. See "SECURITY CONSIDERATIONS" above for important
   * @notice principles to keep in mind when implementing your fulfillRandomness
   * @notice method.
   *
   * @dev VRFConsumerBaseV2 expects its subcontracts to have a method with this
   * @dev signature, and will call it once it has verified the proof
   * @dev associated with the randomness. (It is triggered via a call to
   * @dev rawFulfillRandomness, below.)
   *
   * @param requestId The Id initially returned by requestRandomness
   * @param randomWords the VRF output expanded to the requested number of words
   */
  function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal virtual;

  // rawFulfillRandomness is called by VRFCoordinator when it receives a valid VRF
  // proof. rawFulfillRandomness then calls fulfillRandomness, after validating
  // the origin of the call
  function rawFulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external {
    if (msg.sender != vrfCoordinator) {
      revert OnlyCoordinatorCanFulfill(msg.sender, vrfCoordinator);
    }
    fulfillRandomWords(requestId, randomWords);
  }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface VRFCoordinatorV2Interface {
  /**
   * @notice Get configuration relevant for making requests
   * @return minimumRequestConfirmations global min for request confirmations
   * @return maxGasLimit global max for request gas limit
   * @return s_provingKeyHashes list of registered key hashes
   */
  function getRequestConfig()
    external
    view
    returns (
      uint16,
      uint32,
      bytes32[] memory
    );

  /**
   * @notice Request a set of random words.
   * @param keyHash - Corresponds to a particular oracle job which uses
   * that key for generating the VRF proof. Different keyHash's have different gas price
   * ceilings, so you can select a specific one to bound your maximum per request cost.
   * @param subId  - The ID of the VRF subscription. Must be funded
   * with the minimum subscription balance required for the selected keyHash.
   * @param minimumRequestConfirmations - How many blocks you'd like the
   * oracle to wait before responding to the request. See SECURITY CONSIDERATIONS
   * for why you may want to request more. The acceptable range is
   * [minimumRequestBlockConfirmations, 200].
   * @param callbackGasLimit - How much gas you'd like to receive in your
   * fulfillRandomWords callback. Note that gasleft() inside fulfillRandomWords
   * may be slightly less than this amount because of gas used calling the function
   * (argument decoding etc.), so you may need to request slightly more than you expect
   * to have inside fulfillRandomWords. The acceptable range is
   * [0, maxGasLimit]
   * @param numWords - The number of uint256 random values you'd like to receive
   * in your fulfillRandomWords callback. Note these numbers are expanded in a
   * secure way by the VRFCoordinator from a single random value supplied by the oracle.
   * @return requestId - A unique identifier of the request. Can be used to match
   * a request to a response in fulfillRandomWords.
   */
  function requestRandomWords(
    bytes32 keyHash,
    uint64 subId,
    uint16 minimumRequestConfirmations,
    uint32 callbackGasLimit,
    uint32 numWords
  ) external returns (uint256 requestId);

  /**
   * @notice Create a VRF subscription.
   * @return subId - A unique subscription id.
   * @dev You can manage the consumer set dynamically with addConsumer/removeConsumer.
   * @dev Note to fund the subscription, use transferAndCall. For example
   * @dev  LINKTOKEN.transferAndCall(
   * @dev    address(COORDINATOR),
   * @dev    amount,
   * @dev    abi.encode(subId));
   */
  function createSubscription() external returns (uint64 subId);

  /**
   * @notice Get a VRF subscription.
   * @param subId - ID of the subscription
   * @return balance - LINK balance of the subscription in juels.
   * @return reqCount - number of requests for this subscription, determines fee tier.
   * @return owner - owner of the subscription.
   * @return consumers - list of consumer address which are able to use this subscription.
   */
  function getSubscription(uint64 subId)
    external
    view
    returns (
      uint96 balance,
      uint64 reqCount,
      address owner,
      address[] memory consumers
    );

  /**
   * @notice Request subscription owner transfer.
   * @param subId - ID of the subscription
   * @param newOwner - proposed new owner of the subscription
   */
  function requestSubscriptionOwnerTransfer(uint64 subId, address newOwner) external;

  /**
   * @notice Request subscription owner transfer.
   * @param subId - ID of the subscription
   * @dev will revert if original owner of subId has
   * not requested that msg.sender become the new owner.
   */
  function acceptSubscriptionOwnerTransfer(uint64 subId) external;

  /**
   * @notice Add a consumer to a VRF subscription.
   * @param subId - ID of the subscription
   * @param consumer - New consumer which can use the subscription
   */
  function addConsumer(uint64 subId, address consumer) external;

  /**
   * @notice Remove a consumer from a VRF subscription.
   * @param subId - ID of the subscription
   * @param consumer - Consumer to remove from the subscription
   */
  function removeConsumer(uint64 subId, address consumer) external;

  /**
   * @notice Cancel a subscription
   * @param subId - ID of the subscription
   * @param to - Where to send the remaining LINK to
   */
  function cancelSubscription(uint64 subId, address to) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (token/ERC721/extensions/ERC721Burnable.sol)

pragma solidity ^0.8.0;

import "../ERC721.sol";
import "../../../utils/Context.sol";

/**
 * @title ERC721 Burnable Token
 * @dev ERC721 Token that can be burned (destroyed).
 */
abstract contract ERC721Burnable is Context, ERC721 {
    /**
     * @dev Burns `tokenId`. See {ERC721-_burn}.
     *
     * Requirements:
     *
     * - The caller must own `tokenId` or be an approved operator.
     */
    function burn(uint256 tokenId) public virtual {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: caller is not token owner nor approved");
        _burn(tokenId);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (utils/Strings.sol)

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

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

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)

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
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (token/ERC721/ERC721.sol)

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
        require(owner != address(0), "ERC721: address zero is not a valid owner");
        return _balances[owner];
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: invalid token ID");
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
        _requireMinted(tokenId);

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overridden in child contracts.
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
            "ERC721: approve caller is not token owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        _requireMinted(tokenId);

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        _setApprovalForAll(_msgSender(), operator, approved);
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
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: caller is not token owner nor approved");

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
        bytes memory data
    ) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: caller is not token owner nor approved");
        _safeTransfer(from, to, tokenId, data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `data` is additional data, it has no specified format and it is sent in call to `to`.
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
        bytes memory data
    ) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, data), "ERC721: transfer to non ERC721Receiver implementer");
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
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || isApprovedForAll(owner, spender) || getApproved(tokenId) == spender);
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
        bytes memory data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, data),
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

        _afterTokenTransfer(address(0), to, tokenId);
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

        _afterTokenTransfer(owner, address(0), tokenId);
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
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer from incorrect owner");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);

        _afterTokenTransfer(from, to, tokenId);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits an {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Approve `operator` to operate on all of `owner` tokens
     *
     * Emits an {ApprovalForAll} event.
     */
    function _setApprovalForAll(
        address owner,
        address operator,
        bool approved
    ) internal virtual {
        require(owner != operator, "ERC721: approve to caller");
        _operatorApprovals[owner][operator] = approved;
        emit ApprovalForAll(owner, operator, approved);
    }

    /**
     * @dev Reverts if the `tokenId` has not been minted yet.
     */
    function _requireMinted(uint256 tokenId) internal view virtual {
        require(_exists(tokenId), "ERC721: invalid token ID");
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) private returns (bool) {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    /// @solidity memory-safe-assembly
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

    /**
     * @dev Hook that is called after any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
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
// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (utils/Address.sol)

pragma solidity ^0.8.1;

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
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
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
                /// @solidity memory-safe-assembly
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
// OpenZeppelin Contracts v4.4.1 (token/ERC721/extensions/IERC721Metadata.sol)

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
// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC721/IERC721Receiver.sol)

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
     * The selector can be obtained in Solidity with `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (token/ERC721/IERC721.sol)

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

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or {setApprovalForAll}.
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
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)

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
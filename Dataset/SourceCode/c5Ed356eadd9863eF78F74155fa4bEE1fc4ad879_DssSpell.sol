/**
 *Submitted for verification at Etherscan.io on 2021-05-07
*/

// hevm: flattened sources of src/DssSpell.sol
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity =0.6.12 >=0.5.12 >=0.6.12 <0.7.0;

////// lib/dss-exec-lib/src/DssExecLib.sol
//
// DssExecLib.sol -- MakerDAO Executive Spellcrafting Library
//
// Copyright (C) 2020 Maker Ecosystem Growth Holdings, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
/* pragma solidity ^0.6.12; */
/* pragma experimental ABIEncoderV2; */

interface Fileable {
    function file(bytes32, address) external;
    function file(bytes32, uint256) external;
    function file(bytes32, bytes32, uint256) external;
    function file(bytes32, bytes32, address) external;
}

// https://github.com/makerdao/dss-chain-log
interface ChainlogLike {
    function setVersion(string calldata) external;
    function setIPFS(string calldata) external;
    function setSha256sum(string calldata) external;
    function getAddress(bytes32) external view returns (address);
    function setAddress(bytes32, address) external;
    function removeAddress(bytes32) external;
}

library DssExecLib {
    address constant public LOG = 0xdA0Ab1e0017DEbCd72Be8599041a2aa3bA7e740F;
    function vat()        public view returns (address) {}
    function cat()        public view returns (address) {}
    function pot()        public view returns (address) {}
    function vow()        public view returns (address) {}
    function end()        public view returns (address) {}
    function reg()        public view returns (address) {}
    function spotter()    public view returns (address) {}
    function flipperMom() public view returns (address) {}
    function flip(bytes32) public view returns (address) {}
    function getChangelogAddress(bytes32) public view returns (address) {}
    function setChangelogAddress(bytes32, address) public {}
    function setChangelogVersion(string memory) public {}
    function authorize(address, address) public {}
    function deauthorize(address, address) public {}
    function canCast(uint40, bool) public pure returns (bool) {}
    function nextCastTime(uint40, uint40, bool) public pure returns (uint256) {}
    function setContract(address, bytes32, address) public {}
    function setContract(address, bytes32, bytes32, address) public {}
    function setIlkStabilityFee(bytes32, uint256, bool) public {}
    function setIlkLiquidationRatio(bytes32, uint256) public {}
    function decreaseIlkDebtCeiling(bytes32, uint256, bool) public {}
    function setIlkAutoLineParameters(bytes32, uint256, uint256, uint256) public {}
    function addWritersToMedianWhitelist(address, address[] memory) public {}
    function removeWritersFromMedianWhitelist(address, address[] memory) public {}
    function setIlkAutoLineDebtCeiling(bytes32, uint256) public {}
    function addReaderToOSMWhitelist(address, address) public {}
    function removeReaderFromOSMWhitelist(address, address) public {}
    function sendPaymentFromSurplusBuffer(address, uint256) public {}
}

////// lib/dss-exec-lib/src/DssAction.sol
//
// DssAction.sol -- DSS Executive Spell Actions
//
// Copyright (C) 2020 Maker Ecosystem Growth Holdings, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/* pragma solidity ^0.6.12; */

/* import { DssExecLib } from "./DssExecLib.sol"; */

abstract contract DssAction {

    using DssExecLib for *;

    // Modifier used to limit execution time when office hours is enabled
    modifier limited {
        require(DssExecLib.canCast(uint40(block.timestamp), officeHours()), "Outside office hours");
        _;
    }

    // Office Hours defaults to true by default.
    //   To disable office hours, override this function and
    //    return false in the inherited action.
    function officeHours() public virtual returns (bool) {
        return true;
    }

    // DssExec calls execute. We limit this function subject to officeHours modifier.
    function execute() external limited {
        actions();
    }

    // DssAction developer must override `actions()` and place all actions to be called inside.
    //   The DssExec function will call this subject to the officeHours limiter
    //   By keeping this function public we allow simulations of `execute()` on the actions outside of the cast time.
    function actions() public virtual;

    // Returns the next available cast time
    function nextCastTime(uint256 eta) external returns (uint256 castTime) {
        require(eta <= uint40(-1));
        castTime = DssExecLib.nextCastTime(uint40(eta), uint40(block.timestamp), officeHours());
    }
}

////// lib/dss-exec-lib/src/DssExec.sol
//
// DssExec.sol -- MakerDAO Executive Spell Template
//
// Copyright (C) 2020 Maker Ecosystem Growth Holdings, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/* pragma solidity ^0.6.12; */

interface PauseAbstract {
    function delay() external view returns (uint256);
    function plot(address, bytes32, bytes calldata, uint256) external;
    function exec(address, bytes32, bytes calldata, uint256) external returns (bytes memory);
}

interface Changelog {
    function getAddress(bytes32) external view returns (address);
}

interface SpellAction {
    function officeHours() external view returns (bool);
    function nextCastTime(uint256) external view returns (uint256);
}

contract DssExec {

    Changelog      constant public log   = Changelog(0xdA0Ab1e0017DEbCd72Be8599041a2aa3bA7e740F);
    uint256                 public eta;
    bytes                   public sig;
    bool                    public done;
    bytes32       immutable public tag;
    address       immutable public action;
    uint256       immutable public expiration;
    PauseAbstract immutable public pause;

    // Provides a descriptive tag for bot consumption
    // This should be modified weekly to provide a summary of the actions
    // Hash: seth keccak -- "$(wget https://<executive-vote-canonical-post> -q -O - 2>/dev/null)"
    string                  public description;

    function officeHours() external view returns (bool) {
        return SpellAction(action).officeHours();
    }

    function nextCastTime() external view returns (uint256 castTime) {
        return SpellAction(action).nextCastTime(eta);
    }

    // @param _description  A string description of the spell
    // @param _expiration   The timestamp this spell will expire. (Ex. now + 30 days)
    // @param _spellAction  The address of the spell action
    constructor(string memory _description, uint256 _expiration, address _spellAction) public {
        pause       = PauseAbstract(log.getAddress("MCD_PAUSE"));
        description = _description;
        expiration  = _expiration;
        action      = _spellAction;

        sig = abi.encodeWithSignature("execute()");
        bytes32 _tag;                    // Required for assembly access
        address _action = _spellAction;  // Required for assembly access
        assembly { _tag := extcodehash(_action) }
        tag = _tag;
    }

    function schedule() public {
        require(now <= expiration, "This contract has expired");
        require(eta == 0, "This spell has already been scheduled");
        eta = now + PauseAbstract(pause).delay();
        pause.plot(action, tag, sig, eta);
    }

    function cast() public {
        require(!done, "spell-already-cast");
        done = true;
        pause.exec(action, tag, sig, eta);
    }
}

////// lib/dss-interfaces/src/dss/ClipAbstract.sol

/// ClipAbstract.sol -- Clip Interface

// Copyright (C) 2021 Maker Ecosystem Growth Holdings, INC.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/* pragma solidity >=0.5.12; */

interface ClipAbstract {
    function wards(address) external view returns (uint256);
    function rely(address) external;
    function deny(address) external;
    function ilk() external view returns (bytes32);
    function vat() external view returns (address);
    function dog() external view returns (address);
    function vow() external view returns (address);
    function spotter() external view returns (address);
    function calc() external view returns (address);
    function buf() external view returns (uint256);
    function tail() external view returns (uint256);
    function cusp() external view returns (uint256);
    function chip() external view returns (uint64);
    function tip() external view returns (uint192);
    function chost() external view returns (uint256);
    function kicks() external view returns (uint256);
    function active(uint256) external view returns (uint256);
    function sales(uint256) external view returns (uint256,uint256,uint256,address,uint96,uint256);
    function stopped() external view returns (uint256);
    function file(bytes32,uint256) external;
    function file(bytes32,address) external;
    function kick(uint256,uint256,address,address) external returns (uint256);
    function redo(uint256,address) external;
    function take(uint256,uint256,uint256,address,bytes calldata) external;
    function count() external view returns (uint256);
    function list() external view returns (uint256[] memory);
    function getStatus(uint256) external view returns (bool,uint256,uint256,uint256);
    function upchost() external;
    function yank(uint256) external;
}

////// lib/dss-interfaces/src/dss/ClipperMomAbstract.sol
/* pragma solidity >=0.5.12; */

// https://github.com/makerdao/Clipper-mom/blob/master/src/ClipperMom.sol
interface ClipperMomAbstract {
    function owner() external view returns (address);
    function authority() external view returns (address);
    function locked(address) external view returns (uint256);
    function tolerance(address) external view returns (uint256);
    function spotter() external view returns (address);
    function setOwner(address) external;
    function setAuthority(address) external;
    function setPriceTolerance(address, uint256) external;
    function setBreaker(address, uint256, uint256) external;
    function tripBreaker(address) external;
}

////// src/DssSpell.sol
// Copyright (C) 2021 Maker Ecosystem Growth Holdings, INC.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/* pragma solidity 0.6.12; */

/* import {Fileable, ChainlogLike} from "dss-exec-lib/DssExecLib.sol"; */
/* import "dss-exec-lib/DssExec.sol"; */
/* import "dss-exec-lib/DssAction.sol"; */
/* import "dss-interfaces/dss/ClipAbstract.sol"; */
/* import "dss-interfaces/dss/ClipperMomAbstract.sol"; */

struct Collateral {
    bytes32 ilk;
    address vat;
    address vow;
    address spotter;
    address cat;
    address dog;
    address end;
    address esm;
    address flipperMom;
    address clipperMom;
    address ilkRegistry;
    address pip;
    address clipper;
    address flipper;
    address calc;
    uint256 hole;
    uint256 chop;
    uint256 buf;
    uint256 tail;
    uint256 cusp;
    uint256 chip;
    uint256 tip;
    uint256 cut;
    uint256 step;
    uint256 tolerance;
    bytes32 clipKey;
    bytes32 calcKey;
    bytes32 flipKey;
}

contract DssSpellAction is DssAction {

    // Provides a descriptive tag for bot consumption
    // This should be modified weekly to provide a summary of the actions
    // Hash: seth keccak -- "$(wget https://raw.githubusercontent.com/makerdao/community/e335ac403896cd9eb76c7f76ee4970350d6fc004/governance/votes/Executive%20vote%20-%20May%207%2C%202021.md -q -O - 2> /dev/null)"
    string public constant description =
        "2021-05-07 MakerDAO Executive Spell | Hash: 0x4b0e918bfb1160fd1bf3db6b84896b364fbf934389c28b62cd630afe24ce4087";

    uint256 constant WAD = 10**18;
    uint256 constant RAY = 10**27;
    uint256 constant RAD = 10**45;

    address constant MCD_CLIP_BAT_A             = 0x3D22e6f643e2F4c563fD9db22b229Cbb0Cd570fb;
    address constant MCD_CLIP_CALC_BAT_A        = 0x2e118153D304a0d9C5838D5FCb70CEfCbEc81DC2;
    address constant MCD_CLIP_ZRX_A             = 0xdc90d461E148552387f3aB3EBEE0Bdc58Aa16375;
    address constant MCD_CLIP_CALC_ZRX_A        = 0xebe5e9D77b9DBBA8907A197f4c2aB00A81fb0C4e;
    address constant MCD_CLIP_KNC_A             = 0x006Aa3eB5E666D8E006aa647D4afAB212555Ddea;
    address constant MCD_CLIP_CALC_KNC_A        = 0x82c41e2ADE28C066a5D3A1E3f5B444a4075C1584;
    address constant MCD_CLIP_MANA_A            = 0xF5C8176E1eB0915359E46DEd16E52C071Bb435c0;
    address constant MCD_CLIP_CALC_MANA_A       = 0xABbCd14FeDbb2D39038327055D9e615e178Fd64D;
    address constant MCD_CLIP_COMP_A            = 0x2Bb690931407DCA7ecE84753EA931ffd304f0F38;
    address constant MCD_CLIP_CALC_COMP_A       = 0x1f546560EAa70985d962f1562B65D4B182341a63;
    address constant MCD_CLIP_LRC_A             = 0x81C5CDf4817DBf75C7F08B8A1cdaB05c9B3f70F7;
    address constant MCD_CLIP_CALC_LRC_A        = 0x6856CCA4c881CAf29B6563bA046C7Bb73121fb9d;
    address constant MCD_CLIP_BAL_A             = 0x6AAc067bb903E633A422dE7BE9355E62B3CE0378;
    address constant MCD_CLIP_CALC_BAL_A        = 0x79564a41508DA86721eDaDac07A590b5A51B2c01;
    address constant MCD_CLIP_UNI_A             = 0x3713F83Ee6D138Ce191294C131148176015bC29a;
    address constant MCD_CLIP_CALC_UNI_A        = 0xeA7FE6610e6708E2AFFA202948cA19ace3F580AE;
    address constant MCD_CLIP_RENBTC_A          = 0x834719BEa8da68c46484E001143bDDe29370a6A3;
    address constant MCD_CLIP_CALC_RENBTC_A     = 0xcC89F368aad8D424d3e759c1525065e56019a0F4;
    address constant MCD_CLIP_AAVE_A            = 0x8723b74F598DE2ea49747de5896f9034CC09349e;
    address constant MCD_CLIP_CALC_AAVE_A       = 0x76024a8EfFCFE270e089964a562Ece6ea5f3a14C;

    address constant GOV_MULSTISIG  = 0x73f09254a81e1F835Ee442d1b3262c1f1d7A13ff;
    address constant RISK_MULSTISIG = 0xd98ef20520048a35EdA9A202137847A62120d2d9;
    address constant RWF_MULSTISIG  = 0x9e1585d9CA64243CE43D42f7dD7333190F66Ca09;
    address constant GRO_MULSTISIG  = 0x7800C137A645c07132886539217ce192b9F0528e;
    address constant CP_MULSTISIG   = 0x6A0Ce7dBb43Fe537E3Fd0Be12dc1882393895237;

    uint256 constant GOV_MONTHLY_EXPENSE  = 80_000;
    uint256 constant RISK_MONTHLY_EXPENSE = 100_500;
    uint256 constant RWF_MONTHLY_EXPENSE  = 40_000;
    uint256 constant GRO_MONTHLY_EXPENSE  = 126_117;
    uint256 constant CP_MONTHLY_EXPENSE   = 44_375;

    function flipperToClipper(Collateral memory col) internal {
        // Check constructor values of Clipper
        require(ClipAbstract(col.clipper).vat() == col.vat, "DssSpell/clip-wrong-vat");
        require(ClipAbstract(col.clipper).spotter() == col.spotter, "DssSpell/clip-wrong-spotter");
        require(ClipAbstract(col.clipper).dog() == col.dog, "DssSpell/clip-wrong-dog");
        require(ClipAbstract(col.clipper).ilk() == col.ilk, "DssSpell/clip-wrong-ilk");
        // Set CLIP for the ilk in the DOG
        DssExecLib.setContract(col.dog, col.ilk, "clip", col.clipper);
        // Set VOW in the CLIP
        DssExecLib.setContract(col.clipper, "vow", col.vow);
        // Set CALC in the CLIP
        DssExecLib.setContract(col.clipper, "calc", col.calc);
        // Authorize CLIP can access to VAT
        DssExecLib.authorize(col.vat, col.clipper);
        // Authorize CLIP can access to DOG
        DssExecLib.authorize(col.dog, col.clipper);
        // Authorize DOG can kick auctions on CLIP
        DssExecLib.authorize(col.clipper, col.dog);
        // Authorize the END to access the CLIP
        DssExecLib.authorize(col.clipper, col.end);
        // Authorize CLIPPERMOM can set the stopped flag in CLIP
        DssExecLib.authorize(col.clipper, col.clipperMom);
        // Authorize ESM to execute in Clipper
        DssExecLib.authorize(col.clipper, col.esm);
        // Whitelist CLIP in the osm
        DssExecLib.addReaderToOSMWhitelist(col.pip, col.clipper);
        // Whitelist clipperMom in the osm
        DssExecLib.addReaderToOSMWhitelist(col.pip, col.clipperMom);
        // No more auctions kicked via the CAT:
        DssExecLib.deauthorize(col.flipper, col.cat);
        // No more circuit breaker for the FLIP:
        DssExecLib.deauthorize(col.flipper, col.flipperMom);
        // Set values
        Fileable(col.dog).file(col.ilk, "hole", col.hole);
        Fileable(col.dog).file(col.ilk, "chop", col.chop);
        Fileable(col.clipper).file("buf", col.buf);
        Fileable(col.clipper).file("tail", col.tail);
        Fileable(col.clipper).file("cusp", col.cusp);
        Fileable(col.clipper).file("chip", col.chip);
        Fileable(col.clipper).file("tip", col.tip);
        Fileable(col.calc).file("cut", col.cut);
        Fileable(col.calc).file("step", col.step);
        ClipperMomAbstract(col.clipperMom).setPriceTolerance(col.clipper, col.tolerance);
        // Update chost
        ClipAbstract(col.clipper).upchost();
        // Replace flip to clip in the ilk registry
        DssExecLib.setContract(col.ilkRegistry, col.ilk, "xlip", col.clipper);
        Fileable(col.ilkRegistry).file(col.ilk, "class", 1);
        // Update Chainlog
        DssExecLib.setChangelogAddress(col.clipKey, col.clipper);
        DssExecLib.setChangelogAddress(col.calcKey, col.calc);
        ChainlogLike(DssExecLib.LOG).removeAddress(col.flipKey);
    }

    function actions() public override {
        address MCD_VAT         = DssExecLib.vat();
        address MCD_CAT         = DssExecLib.cat();
        address MCD_DOG         = DssExecLib.getChangelogAddress("MCD_DOG");
        address MCD_VOW         = DssExecLib.vow();
        address MCD_SPOT        = DssExecLib.spotter();
        address MCD_END         = DssExecLib.end();
        address MCD_ESM         = DssExecLib.getChangelogAddress("MCD_ESM");
        address FLIPPER_MOM     = DssExecLib.getChangelogAddress("FLIPPER_MOM");
        address CLIPPER_MOM     = DssExecLib.getChangelogAddress("CLIPPER_MOM");
        address ILK_REGISTRY    = DssExecLib.getChangelogAddress("ILK_REGISTRY");

        // -------------------- UNIV2DAIUSDC-A Adjust liq ratio --------------------
        DssExecLib.setIlkLiquidationRatio("UNIV2DAIUSDC-A", 10500);

        // --------------------------------- BAT-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "BAT-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_BAT"),
            clipper: MCD_CLIP_BAT_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_BAT_A"),
            calc: MCD_CLIP_CALC_BAT_A,
            hole: 1_500_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_BAT_A",
            calcKey: "MCD_CLIP_CALC_BAT_A",
            flipKey: "MCD_FLIP_BAT_A"
        }));

        // --------------------------------- ZRX-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "ZRX-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_ZRX"),
            clipper: MCD_CLIP_ZRX_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_ZRX_A"),
            calc: MCD_CLIP_CALC_ZRX_A,
            hole: 1_000_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_ZRX_A",
            calcKey: "MCD_CLIP_CALC_ZRX_A",
            flipKey: "MCD_FLIP_ZRX_A"
        }));

        // --------------------------------- KNC-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "KNC-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_KNC"),
            clipper: MCD_CLIP_KNC_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_KNC_A"),
            calc: MCD_CLIP_CALC_KNC_A,
            hole: 500_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_KNC_A",
            calcKey: "MCD_CLIP_CALC_KNC_A",
            flipKey: "MCD_FLIP_KNC_A"
        }));

        // --------------------------------- MANA-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "MANA-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_MANA"),
            clipper: MCD_CLIP_MANA_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_MANA_A"),
            calc: MCD_CLIP_CALC_MANA_A,
            hole: 1_000_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_MANA_A",
            calcKey: "MCD_CLIP_CALC_MANA_A",
            flipKey: "MCD_FLIP_MANA_A"
        }));

        // --------------------------------- COMP-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "COMP-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_COMP"),
            clipper: MCD_CLIP_COMP_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_COMP_A"),
            calc: MCD_CLIP_CALC_COMP_A,
            hole: 2_000_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_COMP_A",
            calcKey: "MCD_CLIP_CALC_COMP_A",
            flipKey: "MCD_FLIP_COMP_A"
        }));

        // --------------------------------- LRC-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "LRC-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_LRC"),
            clipper: MCD_CLIP_LRC_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_LRC_A"),
            calc: MCD_CLIP_CALC_LRC_A,
            hole: 500_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_LRC_A",
            calcKey: "MCD_CLIP_CALC_LRC_A",
            flipKey: "MCD_FLIP_LRC_A"
        }));

        // --------------------------------- BAL-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "BAL-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_BAL"),
            clipper: MCD_CLIP_BAL_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_BAL_A"),
            calc: MCD_CLIP_CALC_BAL_A,
            hole: 3_000_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_BAL_A",
            calcKey: "MCD_CLIP_CALC_BAL_A",
            flipKey: "MCD_FLIP_BAL_A"
        }));

        // --------------------------------- UNI-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "UNI-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_UNI"),
            clipper: MCD_CLIP_UNI_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_UNI_A"),
            calc: MCD_CLIP_CALC_UNI_A,
            hole: 5_000_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_UNI_A",
            calcKey: "MCD_CLIP_CALC_UNI_A",
            flipKey: "MCD_FLIP_UNI_A"
        }));

        // --------------------------------- RENBTC-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "RENBTC-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_RENBTC"),
            clipper: MCD_CLIP_RENBTC_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_RENBTC_A"),
            calc: MCD_CLIP_CALC_RENBTC_A,
            hole: 3_000_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_RENBTC_A",
            calcKey: "MCD_CLIP_CALC_RENBTC_A",
            flipKey: "MCD_FLIP_RENBTC_A"
        }));

        // --------------------------------- AAVE-A ---------------------------------
        flipperToClipper(Collateral({
            ilk: "AAVE-A",
            vat: MCD_VAT,
            vow: MCD_VOW,
            spotter: MCD_SPOT,
            cat: MCD_CAT,
            dog: MCD_DOG,
            end: MCD_END,
            esm: MCD_ESM,
            flipperMom: FLIPPER_MOM,
            clipperMom: CLIPPER_MOM,
            ilkRegistry: ILK_REGISTRY,
            pip: DssExecLib.getChangelogAddress("PIP_AAVE"),
            clipper: MCD_CLIP_AAVE_A,
            flipper: DssExecLib.getChangelogAddress("MCD_FLIP_AAVE_A"),
            calc: MCD_CLIP_CALC_AAVE_A,
            hole: 5_000_000 * RAD,
            chop: 113 * WAD / 100,
            buf: 130 * RAY / 100,
            tail: 140 minutes,
            cusp: 40 * RAY / 100,
            chip: 1 * WAD / 1000,
            tip: 0,
            cut: 99 * RAY / 100,
            step: 90 seconds,
            tolerance: 50 * RAY / 100,
            clipKey: "MCD_CLIP_AAVE_A",
            calcKey: "MCD_CLIP_CALC_AAVE_A",
            flipKey: "MCD_FLIP_AAVE_A"
        }));

        // ------------------------- Update Chainlog -------------------------

        DssExecLib.setChangelogVersion("1.6.0");

        // ----------------------- Core Units Payments -----------------------
        // GovAlpha
        DssExecLib.sendPaymentFromSurplusBuffer(GOV_MULSTISIG, GOV_MONTHLY_EXPENSE);
        // Risk
        DssExecLib.sendPaymentFromSurplusBuffer(RISK_MULSTISIG, RISK_MONTHLY_EXPENSE);
        // Real World Finance
        DssExecLib.sendPaymentFromSurplusBuffer(RWF_MULSTISIG, RWF_MONTHLY_EXPENSE);
        // Growth
        DssExecLib.sendPaymentFromSurplusBuffer(GRO_MULSTISIG, GRO_MONTHLY_EXPENSE);
        // Content Production
        DssExecLib.sendPaymentFromSurplusBuffer(CP_MULSTISIG, CP_MONTHLY_EXPENSE);
    }
}

contract DssSpell is DssExec {
    DssSpellAction internal action_ = new DssSpellAction();
    constructor() DssExec(action_.description(), block.timestamp + 30 days, address(action_)) public {}
}
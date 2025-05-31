
# [M-01] Signature Malleability in is possible in the permit Function

### Severity
Impact: Medium

Likelihood: Medium  

### Description

The `permit` function in the `Staker.sol` contract does not restrict the ECDSA signature’s `s value` to the lower half of the secp256k1 curve’s order `(s <= N/2, where N is 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)`. This enables signature malleability, allowing a valid signature `(r, s, v)` to be transformed into another valid signature `(r, N - s, v')` without the private key.
An attacker can exploit this by observing a user’s permit transaction in the mempool, computing the malleable signature, and submitting it with higher gas fees. If the attacker’s transaction is mined first, it consumes the user’s nonce `(nonces[owner])`, incrementing it from `n to n+1`. The user’s transaction then fails as the nonce in their signature `(n)` no longer matches `nonces[owner] (n+1)`, reverting with `InvalidSigner()`.

```solidity
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        if (deadline < block.timestamp) revert PermitDeadlineExpired();

        // Unchecked because the only math done is incrementing
        // the owner's nonce which cannot realistically overflow.
        unchecked {
            address recoveredAddress = ecrecover(
                keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256(
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                                ),
                                owner,
                                spender,
                                value,
                                nonces[owner]++,
                                deadline
                            )
                        )
                    )
                ),
                v,
                r,
                s
            );

            if (recoveredAddress == address(0) || recoveredAddress != owner) revert InvalidSigner();

            allowance[recoveredAddress][spender] = value;
        }

        emit Approval(owner, spender, value);
    }
```
The lack of a check on the `s` value allows an attacker to submit a malleable signature, consuming the nonce and causing the user’s transaction to revert. This disrupts user transactions and potentially breaking downstream logic dependent on successful permit calls.

### Recommendations

Enforce s <= N/2 by adding the following check before the ecrecover call:
```solidity
if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert InvalidSigner();
```


# [L-01] Type Mismatch in OracleInitialized and UniswapOracleProbed Events
### Summary
A type mismatch exists between the interface (`IOracle`) and implementation (`Oracle`) for the `avLiquidity` parameter in the `OracleInitialized` and `UniswapOracleProbed` events. The interface defines `avLiquidity` as `uint160`, while the implementation uses `uint136`.

### Vulnerability Details
- In the `IOracle` interface:
  - `OracleInitialized` event: `avLiquidity` is `uint160`.
  - `UniswapOracleProbed` event: `avLiquidity` is `uint160`.
- In the `Oracle` contract:
  - `OracleInitialized` event: `avLiquidity` is `uint136`.
  - `UniswapOracleProbed` event: `avLiquidity` is `uint136`.
- The mismatch occurs because the implementation uses `uint136` for `avLiquidity` (aligned with the `UniswapOracleData` struct), while the interface expects `uint160`.

### Impact
- ABI encoding/decoding inconsistencies may occur when interacting with the contract via the interface.
- Off-chain applications parsing events may encounter errors or misinterpret data, expecting `uint160` instead of `uint136`.
- Potential integration issues with tools or contracts relying on the interface's event signature.

### Tools Used
- Manual code review

### Recommended Mitigation
Update the `IOracle` interface to use `uint136` for `avLiquidity` in both events to match the implementation:

```solidity
event OracleInitialized(
    address indexed token0,
    address indexed token1,
    uint24 indexed feeTierSelected,
    uint136 avLiquidity,
    uint40 period
);

event UniswapOracleProbed(
    uint24 fee,
    uint136 avLiquidity,
    uint40 period,
    uint16 cardinalityToIncrease
);
```

# [L-02] Missing Input Validation In The stake Fucntion
### Summary
The `stake(uint80 amount)` function does not validate whether the input amount is greater than zero. As a result, it is possible for users to call the function with a zero value, leading to unnecessary state reads and writes, gas consumption, and emission of meaningless events.

### Vulnerability Details
```
function stake(uint80 amount) public {
    ...
    uint80 newBalanceOfSIR = balance.balanceOfSIR - amount;

    unchecked {
        balances[msg.sender] = Balance(newBalanceOfSIR, _dividends(...));
        stakerParams.stake += amount;
        ...
        emit Transfer(msg.sender, STAKING_VAULT, amount);
    }
}
```
When `amount == 0`, the function performs no meaningful state updates but still emits a Transfer event and consumes gas.

### Impact
- Users (or bots) can invoke the function with zero-value stakes, causing unnecessary computation and state transitions.

- Emitting Transfer events with a zero amount can pollute the on-chain event history, making it harder to audit and increasing log indexing bloat.

- Repeated zero-value transactions serve no useful purpose and may open the door to low-cost denial-of-service spam under certain conditions.

### Recommended Mitigation
Add a validation check to ensure that the staked amount is strictly greater than zero:

```solidity
require(amount > 0, "Cannot stake zero amount");
```
This prevents no-op transactions, improves clarity, and reduces unnecessary state changes and event emissions.

# [L-03] Incorrect Tax Constraint Enforcement in StartLiquidityMining and ChangeLiquidityMining

### Vulnerability Details
`SirStructs` library specifies that vault taxes must satisfy `Σ_i (tax_i / type(uint8).max)^2 ≤ 0.1^2`. The `StartLiquidityMining` script sets `newTaxes[0] = 228`, `newTaxes[1] = 114`, yielding `(228/255)^2 + (114/255)^2 ≈ 0.998 < 0.01`. However, neither the script nor the `updateVaultsIssuances` function in `ISystemControl` programmatically validates this constraint. If the implementation fails to enforce it, adding more vaults or higher taxes could violate the constraint, causing reverts or incorrect reward distributions.

### Impact

- Violation of the tax constraint could halt vault updates or misallocate SIR rewards, affecting protocol fairness.

### Recommended Mitigation
Add a check in `updateVaultsIssuances` to enforce the tax constraint. Update scripts to validate taxes before submission.

# [L-04] Undocumented Fee on TEA Token Minting

### Summary
The protocol documentation, specifically the section detailing the fee structure, focuses on fees generated from the minting and burning of APE tokens, which reward Liquidity Providers ("Gentlemen"). However, this documentation omits that a fee is also levied on Liquidity Providers themselves when they mint TEA tokens (i.e., when providing liquidity). The smart contracts implement this TEA minting fee, with the collected portion contributing to Protocol Owned Liquidity (POL). This discrepancy can lead to a misunderstanding of the complete fee mechanics for Liquidity Providers.

### Description of Issue

The provided documentation snippet concerning fees states

```
Vaults feature a fee system that rewards the gentlemen with significant fees from the minting and burning of APE tokens. These fees vary by vault, increasing with the vault's leverage ratio. Although these fees are substantial, they allow apes to hold APE tokens without incurring any maintenance fees, regardless of the holding period. The fees for minting or burning APE tokens are on par with the costs of holding a margin position for approximately one year, striking a balance between potential returns and upfront costs. This structure aims to benefit liquidity providers and encourage long-term traders, while short-term traders may not see their speculative positions fully materialize, essentially contributing more to the ecosystem's finances through these initial fees.
```

This section exclusively describes fees related to APE token activities and their role in rewarding Liquidity Providers. It does not mention any fees applicable to Liquidity Providers when they mint TEA tokens.

However, an examination of the ```Vault.sol``` and ```TEA.sol``` contracts reveals the implementation of such a fee:

- ```Vault.sol - _mint function:``` When a user mints TEA tokens (```isAPE == false```), the ```_mint``` function calls the mint function inherited from ```TEA.sol```. A comment within this block explicitly notes the distribution of fees to Protocol Owned Liquidity:

```solidity
// In Vault.sol, _mint function
// ...
} else {
    // Mint TEA and distribute fees to protocol owned liquidity (POL)
    (fees, amount) = mint( // This calls the mint function from TEA.sol
        minter,
        vaultParams.collateralToken,
        vaultState.vaultId,
        systemParams_,
        vaultIssuanceParams_,
        reserves,
        collateralToDeposit
    );
}
```
 ```TEA.sol - mint function:``` This function, responsible for minting TEA tokens, clearly calculates and applies a fee based on ```systemParams_.lpFee.fee.``` The portion of TEA tokens corresponding to this fee is then minted to the protocol itself (```address(this)```), thereby increasing POL.

```solidity
// In TEA.sol, mint function
// ...
// Split collateralDeposited between minter and POL
fees = Fees.feeMintTEA(collateralDeposited, systemParams_.lpFee.fee);

// Minter's share of TEA
// 'amount' is calculated based on fees.collateralInOrWithdrawn (net collateral)
amount = FullMath.mulDiv(
    amountToPOL,
    fees.collateralInOrWithdrawn,
    // ... (denominator logic) ...
);

// POL's share of TEA
amountToPOL -= amount; // 'amountToPOL' initially represented total TEA from gross deposit

// Update total supply and protocol balance
// ...
totalSupplyAndBalanceVault_.balanceVault += uint128(amountToPOL); // Protocol's TEA balance increases
// ...

// Emit (mint) transfer events
emit TransferSingle(minter, address(0), minter, vaultId, amount); // To minter
emit TransferSingle(minter, address(0), address(this), vaultId, amountToPOL); // Fee portion to protocol (POL)
```
This implemented fee on TEA minting is not reflected in the user-facing documentation regarding the protocol's fee structure.

### Impact

LPs might not be aware that a portion of their deposited collateral is effectively taken as a fee when minting TEA tokens, as the documentation focuses on APE token fees as their reward source. They might expect the amount of TEA tokens received to be directly proportional to their full collateral deposit.


### Recommendation
To ensure full transparency and align documentation with the on-chain behavior, it is recommended to update the protocol's fee documentation. The updated documentation should clearly

1. State that a fee is applied when Liquidity Providers (Gentlemen) mint TEA tokens.
2. Explain the basis for this fee calculation (e.g., derived from ```systemParams_.lpFee.fee```).
3. Describe the purpose and destination of this fee, specifically its contribution to Protocol Owned Liquidity (POL), and briefly explain the benefits of POL to the ecosystem.


# [L-05] Discrepancy in Saturation Price Calculation

### Summary
The ```_updateVaultState``` function calculates and stores a compressed representation of a vault's state, including ```tickPriceSatX42```, which defines the boundary between the "Power Zone" (ideal constant leverage) and the "Saturation Zone" (liquidity-constrained). Within the logic for the Saturation Zone, there is a significant discrepancy between the mathematical formula for the saturation price (```priceSat```) implied by the implemented code and the formula stated in the accompanying code comment. This can lead to the vault operating with an incorrect saturation price threshold, potentially affecting P&L calculations and the transition between operational zones.

### Description of Issue
The issue lies in the calculation of ```tickPriceSatX42``` when ```isPowerZone``` is ```false``` (i.e., the vault is determined to be in the Saturation Zone).

**Commented Intention:** The code comment for the Saturation Zone states the target formula as:

```plaintext
/*
    PRICE IN SATURATION ZONE
    priceSat = r*price*L/R
 */
```
Assuming ```price``` is the current price (```priceCurrent```), this implies ```priceSat / priceCurrent = (r * L) / R```. In tick space, this would translate to: ```tickSat - tickCurrent = tick( (r * L) / R )``` ````tickSat = tickCurrent + tick( (r * L) / R )```

**Implemented Logic (for positive leverageTier):** The code calculates tickRatioX42 as:

```solidity
int256 tickRatioX42 = TickMathPrecision.getTickAtRatio(
    uint256(vaultState.reserve) << absLeverageTier, // Numerator: R * (l-1)
    (uint256(reserves.reserveLPers) << absLeverageTier) + reserves.reserveLPers // Denominator: L * l
);
// Where 'l' is the effective leverage factor (1 + 2^absLeverageTier)
// and 'l-1' is (2^absLeverageTier)
```
So, ```tickRatioX42 = tick( (R * (l-1)) / (L * l) )```.

Then, ```tickPriceSatX42``` is computed as:

```solidity
int256 tempTickPriceSatX42 = reserves.tickPriceX42 - tickRatioX42;
```

This means ```tickSat = tickCurrent - tick( (R * (l-1)) / (L * l) )```.

Converting the implemented logic back to price terms: ```priceSat / priceCurrent = 1 / ( (R * (l-1)) / (L * l) ) priceSat / priceCurrent = (L * l) / (R * (l-1))``` So, ```priceSat = priceCurrent * (L * l) / (R * (l-1))```.

The implemented formula ```priceSat = priceCurrent * (L * l) / (R * (l-1))``` does not match the commented formula ```priceSat = r * price * L / R```. For the two to be equivalent,```r``` would need to be equal to ```l / (l-1)```. If ```r``` is intended to be simply ```l``` (the leverage factor), or another distinct system parameter, the implementation is incorrect relative to the comment.

### Impact
If the commented formula (```priceSat = r*price*L/R```) represents the true intended mathematical model for the saturation price in this zone, then the current implementation is incorrect. This would lead to:

- Incorrect ```tickPriceSatX42``` Storage: The on-chain ```tickPriceSatX42``` will not accurately reflect the intended saturation threshold.
- The point at which the vault's behavior (and thus P&L calculations for LPers and Apes) transitions from the Power Zone to the Saturation Zone (and vice-versa, as determined by comparing the current market price tick with ```tickPriceSatX42``` in the ```VaultExternal.getReserves``` function) will be based on this potentially incorrect value.
- Depending on how ```tickPriceSatX42``` influences the distribution of value between LPers and Apes (especially how ```reserveApes``` and ```reserveLPers``` are calculated in ```VaultExternal._getReserves``` based on this stored ```tickPriceSatX42```), an incorrect saturation threshold could lead to unfair or unintended economic outcomes for participants. For example, it might cause the system to enter or exit the "fixed DBT value for LPs" mode at the wrong price points.

### Recommendation

If the formula in the comment** (```priceSat = r*price*L/R```) is correct, the Solidity implementation for calculating ```tickRatioX42``` and its subsequent application (addition or subtraction, and the ratio itself) must be revised to accurately reflect this formula.

If the current code's derived formula** (```priceSat = priceCurrent * (L*l) / (R*(l-1))```) is correct and intended, then the comment must be updated to accurately describe the implemented logic. The definition and role of ```r``` (if it's different from ```l/(l-1)```) would also need clarification.


# [L-06] Inconsistent Staker Fee Calculation and Documentation in feeAPE

### Summary
The ```feeAPE``` function in the ```Fees.sol``` library calculates fees paid by users ("Apes") when minting or burning APE tokens. A portion of this fee is intended for SIR stakers, determined by a ```tax``` parameter. However, there is a significant discrepancy between the NatSpec documentation, an inline code comment, and the actual implemented formula regarding the percentage of the total fee allocated to stakers. This inconsistency can lead to misconfiguration, incorrect expectations about fee distribution, and reduced clarity of the protocol's economic model.

### Description of Issue
Within the ```feeAPE``` function in ```Fees.sol```, the calculation for ```fees.collateralFeeToStakers``` exhibits conflicting information:

**NatSpec Documentation:**

```solidity
/** @notice APES pay a fee to the LPers when they mint/burn APE
    @notice If a non-zero tax is set for the vault, 10% of the fee is sent to SIR stakers // <-- States 10%
    @param tax Tax in basis points charged to the apes for getting SIR // <-- Describes tax as basis points, but it's uint8
 */
```
The NatSpec suggests that if ```tax``` is non-zero, a fixed ```10%``` of the total APE fee goes to stakers. It also describes ```tax``` as "Tax in basis points," but the parameter type is ```uint8```.

**Inline Code Comment:**

```solidity
// Depending on the tax, between 0 and 20% of the fee is for SIR stakers // <-- States 0-20%
fees.collateralFeeToStakers = uint144((totalFees * tax) / (20 * uint256(type(uint8).max)));
```
An inline comment directly above the calculation suggests the staker's fee portion can range **between 0 and 20%**.

**Actual Implemented Formula:**

```solidity
fees.collateralFeeToStakers = uint144((totalFees * tax) / (20 * uint256(type(uint8).max)));
```
Let's analyze this formula:

- ```tax``` is a ```uint8```, so ```type(uint8).max``` is ```255```.
- The denominator is ```20 * 255 = 5100```.
- **The formula is effectively:** ```fees.collateralFeeToStakers = (totalFees * tax) / 5100```.
- If ```tax = 0```, then ```collateralFeeToStakers = 0```.
- If ```tax = 255``` (the maximum value for a ```uint8```), then: ```collateralFeeToStakers = (totalFees * 255) / (20 * 255) = totalFees / 20 = 0.05 * totalFees```.
- This means the implemented formula results in the stakers receiving **between 0% and 5%** of the ```totalFees```, scaled linearly by the ```tax``` parameter (0-255).
  
There is a clear three-way mismatch:

- NatSpec implies a fixed 10% (if ```tax``` is active).
- Inline comment suggests a 0-20% range.
- The code implements a 0-5% range, scaled by the ```uint8``` tax parameter. Additionally, the NatSpec description of tax as "basis points" conflicts with its ```uint8``` type and how it's used in the 0-5% scaling formula.
  
### Impact
This inconsistency has several negative impacts:

- Users, developers, and auditors relying on the NatSpec or inline comments will have an incorrect understanding of the actual fee distribution to stakers.
- The true percentage of APE fees allocated to stakers is a key economic lever for the protocol. The conflicting information obscures the intended design and actual outcome.
- If governance or administrators set the tax parameter for vaults based on the assumption that it corresponds to a 10% rate or a 0-20% range, the actual staker revenue will be significantly different (0-5%), leading to outcomes that don't match intent.

### Recommendation

- If the current 0-5% scaled by ```uint8 tax``` is the intended logic, then both the NatSpec and the inline comment are incorrect and must be updated. The NatSpec description of ```tax``` as "basis points" also needs correction.
- If, for example, a fixed 10% (when ```tax > 0```) is intended, the formula should be changed to ```fees.collateralFeeToStakers = tax > 0 ? uint144((totalFees * 10) / 100) : 0;```.
- If a 0-20% range scaled by ```uint8 tax``` is intended, the formula should be ```fees.collateralFeeToStakers = uint144((totalFees * tax) / (5 * uint256(type(uint8).max)))```;.
  
Update All Documentation: Once the code reflects the true intention, all NatSpec comments and inline code comments related to this fee calculation must be updated to be consistent and accurately describe the implemented logic and the role of the tax parameter.
  

# [L-07] Unhandled Auction Winner Payment Failures May Result in Fund Loss
### Summary
The `collectFeesAndStartAuction` function in the `Staker.sol` contract does not check the success status of the `_payAuctionWinner` call. If the transfer of the auction lot to the previous winner fails (e.g., due to a problematic token or recipient), the function proceeds as if the payment was successful, causing the previous winner to lose their lot, which is then included in the subsequent auction.

### Finding Description
The `Staker.sol` contract manages token auctions where users bid WETH to win lots of various ERC20 tokens collected as fees. The process involves settling a previous auction and starting a new one via the `collectFeesAndStartAuction` function.

The internal function `_payAuctionWinner(address token, SirStructs.Auction memory auction, address beneficiary)` is designed to transfer the auctioned `token` amount (`auction.bid`) to the `beneficiary` (or `auction.bidder` if `beneficiary` is `address(0)`). Crucially, `_payAuctionWinner` is designed *not* to revert on transfer failure. Instead, it uses low-level calls and returns a boolean: `true` on success, `false` on failure. Failures can occur for various reasons, including:
*   The `token` contract's `transfer` function reverts.
*   The `token` contract's `transfer` function returns `false` (as per some ERC20 implementations).
*   The recipient (`beneficiary` or `auction.bidder`) is unable to receive the tokens (e.g., a blacklisted address for tokens like USDT, a contract that reverts on receiving tokens, or insufficient gas provided for the internal call to the token's `transfer` function if the token's logic is complex).

The `collectFeesAndStartAuction(address token)` function executes the following relevant steps when settling a previous auction for `token`:
1.  It retrieves the details of the previous auction: `SirStructs.Auction memory auction = _auctions[token];`.
2.  It **resets the state for the current token's auction** in storage, effectively erasing the previous winner's details: `_auctions[token] = ... { bidder: address(0), bid: 0, ... };`.
3.  It updates `totalWinningBids` based on the previous auction's bid.
4.  It calls `_distributeDividends()`.
5.  It calls `_payAuctionWinner(token, auction, address(0));` to pay the previous winner.
6.  **It proceeds without checking the boolean return value of `_payAuctionWinner`.**
7.  It then withdraws new fees for the token from the `Vault` using `vault.withdrawFees(token)`.

The security guarantee broken is the **fair distribution of auction winnings**. If the call to `_payAuctionWinner` fails (returns `false`) for any reason other than `auction.bid == 0` (meaning there was a winner to pay, but payment failed), the `collectFeesAndStartAuction` function incorrectly assumes the payment succeeded. Because the previous auction's state (`_auctions[token]`) has already been reset, the previous winner loses their claim to the lot. The tokens that failed to transfer remain in the `Staker.sol` contract and are subsequently included in the lot for the *new* auction when `vault.withdrawFees(token)` is called. The winner of the new auction receives the combined lot, effectively taking the previous winner's assets.

This is in contrast to the `getAuctionLot` function, which correctly checks the return value of `_payAuctionWinner` and reverts if the payment fails, allowing the winner to potentially try claiming again or for the issue to be addressed.

### Impact Explanation
This issue is assessed as **High** severity. A successful exploit or even an accidental trigger (e.g., a user winning an auction for a token that becomes temporarily untransferable) leads to a direct and unrecoverable loss of funds for the user who won the previous auction. Their rightful winnings are effectively stolen and given to the winner of the next auction for the same token. This breaks a core promise of the auction mechanism – that the winner receives the lot they bid on.

### Likelihood Explanation
The likelihood is assessed as **Medium**. While standard tokens like WETH, USDC, or DAI are unlikely to cause `_payAuctionWinner` to fail under normal circumstances, the protocol is designed to auction *any* ERC20 token collected as fees. The broader DeFi ecosystem includes tokens with various non-standard behaviors, such as:
*   **Fee-on-transfer tokens:** Attempting to transfer the exact balance might fail if the token requires a fee deduction from the sender's balance.
*   **Tokens with transfer restrictions:** Blacklisting, whitelisting, pausing, or other access control mechanisms can prevent transfers to specific addresses or under certain conditions.

Given the possibility of such tokens being collected as fees and auctioned, and the fact that transfer failures can occur due to recipient issues (like a blacklisted address) or even temporary network/gas conditions affecting complex token logic, the scenario where `_payAuctionWinner` returns `false` is reasonably likely to occur over the protocol's lifetime. The failure to handle this in a routine function like `collectFeesAndStartAuction` makes the issue a significant risk.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {Addresses} from "src/libraries/Addresses.sol";
import {SystemConstants} from "src/libraries/SystemConstants.sol";
import {Vault} from "src/Vault.sol";
import {Staker} from "src/Staker.sol";
import {IWETH9} from "src/interfaces/IWETH9.sol";
import {ErrorComputation} from "./ErrorComputation.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {TransferHelper} from "v3-core/libraries/TransferHelper.sol";
import {SirStructs} from "src/libraries/SirStructs.sol";
import {APE} from "src/APE.sol";
import {ABDKMath64x64} from "abdk/ABDKMath64x64.sol";

contract Auxiliary is Test {
    address internal constant STAKING_VAULT = 0x000000000051200beef00Add2e55000000000000;

    struct Bidder {
        uint256 id;
        uint96 amount;
    }

    struct TokenBalances {
        uint256 vaultTotalReserves;
        uint256 vaultTotalFees;
        uint256 stakerDonations;
    }

    struct Donations {
        uint96 stakerDonationsETH;
        uint96 stakerDonationsWETH;
    }

    uint256 constant SLOT_SUPPLY = 2;
    uint256 constant SLOT_BALANCES = 5;
    uint256 constant SLOT_INITIALIZED = 3;
    uint256 constant SLOT_TOTAL_RESERVES = 10;

    uint96 constant ETH_SUPPLY = 120e6 * 10 ** 18;

    IWETH9 internal constant WETH = IWETH9(Addresses.ADDR_WETH);

    Staker public staker;
    address public vault;

    /// @dev Auxiliary function for minting SIR tokens
    function _mint(address account, uint80 amount) internal {
        // Increase supply
        uint256 slot = uint256(vm.load(address(staker), bytes32(uint256(SLOT_SUPPLY))));
        uint80 balanceOfSIR = uint80(slot) + amount;
        slot >>= 80;
        uint96 unclaimedETH = uint96(slot);
        vm.store(
            address(staker),
            bytes32(uint256(SLOT_SUPPLY)),
            bytes32(abi.encodePacked(uint80(0), unclaimedETH, balanceOfSIR))
        );
        assertEq(staker.supply(), balanceOfSIR, "Wrong supply slot used by vm.store");

        // Increase balance
        slot = uint256(vm.load(address(staker), keccak256(abi.encode(account, bytes32(uint256(SLOT_BALANCES))))));
        balanceOfSIR = uint80(slot) + amount;
        slot >>= 80;
        unclaimedETH = uint96(slot);
        vm.store(
            address(staker),
            keccak256(abi.encode(account, bytes32(uint256(SLOT_BALANCES)))),
            bytes32(abi.encodePacked(uint80(0), unclaimedETH, balanceOfSIR))
        );
        assertEq(staker.balanceOf(account), balanceOfSIR, "Wrong balance slot used by vm.store");
    }

    function _idToAddress(uint256 id) internal pure returns (address) {
        id = _bound(id, 1, 3);
        return payable(vm.addr(id));
    }

    function _setFees(address token, TokenBalances memory tokenBalances) internal {
        // Bound total reserves and fees
        if (token == Addresses.ADDR_WETH) {
            tokenBalances.vaultTotalFees = _bound(tokenBalances.vaultTotalFees, 0, ETH_SUPPLY);
            if (IERC20(Addresses.ADDR_WETH).balanceOf(vault) > ETH_SUPPLY) {
                tokenBalances.vaultTotalReserves = IERC20(Addresses.ADDR_WETH).balanceOf(vault);
            } else {
                tokenBalances.vaultTotalReserves =
                    _bound(tokenBalances.vaultTotalReserves, IERC20(Addresses.ADDR_WETH).balanceOf(vault), ETH_SUPPLY);
            }
        } else {
            tokenBalances.vaultTotalFees =
                _bound(tokenBalances.vaultTotalFees, 0, type(uint256).max - IERC20(token).totalSupply());
            tokenBalances.vaultTotalReserves = _bound(
                tokenBalances.vaultTotalReserves,
                0,
                type(uint256).max - IERC20(token).totalSupply() - tokenBalances.vaultTotalFees
            );
            if (IERC20(token).balanceOf(vault) > tokenBalances.vaultTotalReserves + tokenBalances.vaultTotalFees) {
                tokenBalances.vaultTotalReserves = IERC20(token).balanceOf(vault) - tokenBalances.vaultTotalFees;
                tokenBalances.vaultTotalFees =
                    _bound(tokenBalances.vaultTotalFees, 0, type(uint256).max - tokenBalances.vaultTotalReserves);
            }
        }

        // Set reserves in Vault
        vm.store(
            vault,
            keccak256(abi.encode(token, bytes32(uint256(SLOT_TOTAL_RESERVES)))),
            bytes32(tokenBalances.vaultTotalReserves)
        );

        // Transfer necessary reserves and fees to Vault
        if (token == Addresses.ADDR_WETH) {
            _dealWETH(
                vault,
                tokenBalances.vaultTotalReserves + tokenBalances.vaultTotalFees
                    - IERC20(Addresses.ADDR_WETH).balanceOf(vault)
            );
        } else {
            _dealToken(
                token,
                vault,
                tokenBalances.vaultTotalReserves + tokenBalances.vaultTotalFees - IERC20(token).balanceOf(vault)
            );
        }

        // Check reserves in Vault are correct
        uint256 totalReserves_ = Vault(vault).totalReserves(token);
        assertEq(tokenBalances.vaultTotalReserves, totalReserves_, "Wrong total reserves slot used by vm.store");
        uint256 vaultTotalFees_ = IERC20(token).balanceOf(vault) - totalReserves_;
        assertEq(tokenBalances.vaultTotalFees, vaultTotalFees_, "Wrong total fees to stakers");

        // Donate tokens to Staker contract
        tokenBalances.stakerDonations =
            _bound(tokenBalances.stakerDonations, 0, type(uint256).max - IERC20(token).totalSupply());
        if (token == Addresses.ADDR_WETH) _dealWETH(address(staker), tokenBalances.stakerDonations);
        else _dealToken(token, address(staker), tokenBalances.stakerDonations);
    }

    function _setDonations(Donations memory donations) internal {
        donations.stakerDonationsWETH = uint96(_bound(donations.stakerDonationsWETH, 0, ETH_SUPPLY));
        donations.stakerDonationsETH = uint96(_bound(donations.stakerDonationsETH, 0, ETH_SUPPLY));

        // Donated (W)ETH to Staker contract
        _dealWETH(address(staker), donations.stakerDonationsWETH);
        _dealETH(address(staker), donations.stakerDonationsETH);
    }

    function _setFeesInVault(address token, TokenBalances memory tokenBalances) internal {
        // Set reserves in Vault
        tokenBalances.vaultTotalReserves =
            _bound(tokenBalances.vaultTotalReserves, 0, type(uint256).max - tokenBalances.vaultTotalFees);
        vm.store(
            vault,
            keccak256(abi.encode(token, bytes32(uint256(SLOT_TOTAL_RESERVES)))),
            bytes32(tokenBalances.vaultTotalReserves)
        );

        // Transfer necessary reserves and fees to Vault
        if (token == Addresses.ADDR_WETH) {
            _dealWETH(
                vault,
                tokenBalances.vaultTotalReserves + tokenBalances.vaultTotalFees
                    - IERC20(Addresses.ADDR_WETH).balanceOf(vault)
            );
        } else {
            _dealToken(
                token,
                vault,
                tokenBalances.vaultTotalReserves + tokenBalances.vaultTotalFees - IERC20(token).balanceOf(vault)
            );
        }

        // Check reserves in Vault are correct
        uint256 totalReserves_ = Vault(vault).totalReserves(token);
        assertEq(tokenBalances.vaultTotalReserves, totalReserves_, "Wrong total reserves slot used by vm.store");
        uint256 vaultTotalFees_ = IERC20(token).balanceOf(vault) - totalReserves_;
        assertEq(tokenBalances.vaultTotalFees, vaultTotalFees_, "Wrong total fees to stakers");
    }

    /// @dev The Foundry deal function is not good for WETH because it doesn't update total supply correctly
    function _dealWETH(address to, uint256 amount) internal {
        hoax(address(1), amount);
        WETH.deposit{value: amount}();
        vm.prank(address(1));
        WETH.transfer(address(to), amount);
    }

    function _dealETH(address to, uint256 amount) internal {
        vm.deal(address(1), amount);
        vm.prank(address(1));
        payable(address(to)).transfer(amount);
    }

    function _dealToken(address token, address to, uint256 amount) internal {
        if (amount == 0) return;
        deal(token, address(1), amount, true);
        vm.prank(address(1));
        TransferHelper.safeTransfer(token, to, amount);
    }

    function _assertAuction(Bidder memory bidder_, uint256 timeStamp) internal view {
        SirStructs.Auction memory auction = staker.auctions(Addresses.ADDR_BNB);
        assertEq(auction.bidder, bidder_.amount == 0 ? address(0) : _idToAddress(bidder_.id), "Wrong bidder");
        assertEq(auction.bid, bidder_.amount, "Wrong bid");
        assertEq(auction.startTime, timeStamp, "Wrong start time");
    }
}

contract StakerTest is Auxiliary {
    using ABDKMath64x64 for int128;

    struct User {
        uint256 id;
        uint80 mintAmount;
        uint80 stakeAmount;
    }

    error NoFeesCollected();
    error NoAuctionLot();
    error AuctionIsNotOver();
    error BidTooLow();
    error NoAuction();
    error NewAuctionCannotStartYet();
    error NotTheAuctionWinner();

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event DividendsPaid(uint96 amountETH, uint80 amountStakedSIR);
    event AuctionStarted(address indexed token, uint256 feesToBeAuctioned);
    event BidReceived(address indexed bidder, address indexed token, uint96 previousBid, uint96 newBid);
    event AuctionedTokensSentToWinner(
        address indexed winner, address indexed beneficiary, address indexed token, uint256 reward
    );

    address alice;
    address bob;
    address charlie;

    function setUp() public {
        vm.createSelectFork("mainnet", 18128102);

        staker = new Staker(Addresses.ADDR_WETH);

        APE ape = new APE();

        vault = address(new Vault(vm.addr(10), address(staker), vm.addr(12), address(ape), Addresses.ADDR_WETH));
        staker.initialize(vault);

        alice = vm.addr(1);
        bob = vm.addr(2);
        charlie = vm.addr(3);
    }
function test_Handle_PayAuctionWinnerFailure() public {
    // --- Setup Users and Mock Token ---
     alice = _idToAddress(1); // Winner of the first auction
     bob = _idToAddress(2);   // Bidder/Winner of the second auction
     address feeCollector = vm.addr(4);

    MockProblematicToken problematicToken = new MockProblematicToken("Problem Token", "PTK", 18);

    uint256 lot1_amount = 100 * 10**18;
    uint256 lot2_amount = 50 * 10**18;

    // Mint tokens to address(1) as _dealToken sources from there
    problematicToken.mint(address(1), lot1_amount + lot2_amount);

    // --- First Auction ---
    // Setup fees for the first auction in the Vault
    TokenBalances memory feesForAuction1;
    feesForAuction1.vaultTotalFees = lot1_amount;
    feesForAuction1.vaultTotalReserves = 0; // All balance in vault is fees
    _setFeesInVault(address(problematicToken), feesForAuction1);

    // Start the first auction
    vm.prank(feeCollector);
    uint256 collectedFees1 = staker.collectFeesAndStartAuction(address(problematicToken));
    assertEq(collectedFees1, lot1_amount, "Collected fees for auction 1 mismatch");
    assertEq(IERC20(problematicToken).balanceOf(address(staker)), lot1_amount, "Staker PTK balance after 1st fee collection mismatch");

    SirStructs.Auction memory auction1_details = staker.auctions(address(problematicToken));
    uint40 auction1_startTime = auction1_details.startTime;

    // Alice bids and wins the first auction
    uint96 bidAmountAlice = uint96(1 ether);
    _dealWETH(alice, bidAmountAlice);
    vm.prank(alice);
    WETH.approve(address(staker), bidAmountAlice);
    vm.prank(alice);
    staker.bid(address(problematicToken), bidAmountAlice);

    // Warp time past auction duration
    vm.warp(auction1_startTime + SystemConstants.AUCTION_DURATION + SystemConstants.AUCTION_COOLDOWN + 1); // Ensure auction is over AND cooldown has passed

    // --- Trigger the Bug: Second call to collectFeesAndStartAuction ---
    // Configure the problematicToken to fail the transfer to Alice
    problematicToken.setFailTransferCondition(alice, 1); // Next 1 transfer to Alice will fail

    // Setup *new* fees for the second auction in the Vault
    TokenBalances memory feesForAuction2;
    feesForAuction2.vaultTotalFees = lot2_amount;
    feesForAuction2.vaultTotalReserves = 0; // All remaining balance in vault is fees for 2nd auction
    // Note: Vault already has lot2_amount from initial minting. _setFeesInVault will adjust.
    _setFeesInVault(address(problematicToken), feesForAuction2);

    uint256 alicePtkBalanceBeforeBug = IERC20(problematicToken).balanceOf(alice);
    uint256 stakerPtkBalanceBeforeBug = IERC20(problematicToken).balanceOf(address(staker)); // Should be lot1_amount

    // Call collectFeesAndStartAuction again. This will attempt to pay Alice (should fail)
    // and then start a new auction with the combined (Alice's unpaid + new) fees.
    vm.prank(feeCollector);
    uint256 collectedFees2 = staker.collectFeesAndStartAuction(address(problematicToken));

    // --- Verification ---
    // 1. Alice should NOT have received her lot1_amount
    assertEq(IERC20(problematicToken).balanceOf(alice), alicePtkBalanceBeforeBug, "Alice's PTK balance should not change due to failed payment");

    // 2. The Staker contract should now hold (lot1_amount from Alice's failed payment) + (lot2_amount new fees)
    // collectedFees2 should be lot2_amount (the fees withdrawn from Vault for the *new* auction)
    assertEq(collectedFees2, lot2_amount, "Collected fees for auction 2 mismatch");
    assertEq(IERC20(problematicToken).balanceOf(address(staker)), lot1_amount + lot2_amount, "Staker should hold Alice's unpaid lot + new fees");

    // 3. A new auction should have started, and its details should reflect an empty bid
    SirStructs.Auction memory auction2_details = staker.auctions(address(problematicToken));
    assertEq(auction2_details.bidder, address(0), "New auction bidder should be address(0)");
    assertEq(auction2_details.bid, 0, "New auction bid should be 0");

    // --- (Optional) Bob wins the second auction and gets the combined lot ---
    uint40 auction2_startTime = auction2_details.startTime;
    uint96 bidAmountBob = uint96(2 ether);
    _dealWETH(bob, bidAmountBob);
    vm.prank(bob);
    WETH.approve(address(staker), bidAmountBob);
    vm.prank(bob);
    staker.bid(address(problematicToken), bidAmountBob);
    vm.warp(auction2_startTime + SystemConstants.AUCTION_DURATION + 1 days);
    uint256 bobPtkBalanceBeforeClaim = IERC20(problematicToken).balanceOf(bob);
    vm.prank(bob);
    staker.getAuctionLot(address(problematicToken), bob);
    assertEq(IERC20(problematicToken).balanceOf(bob), bobPtkBalanceBeforeClaim + lot1_amount + lot2_amount, "Bob should have received the combined lot");
    assertEq(IERC20(problematicToken).balanceOf(address(staker)), 0, "Staker PTK balance should be 0 after Bob claims");
}
   
}

contract MockProblematicToken is IERC20 {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalSupply_;
    string public name_;
    string public symbol_;
    uint8 public decimals_ = 18; // Default to 18 decimals

    address public stakerContractAddress;
    address public failTransferToRecipient;
    uint256 public failTransferCount = 0; // Number of times the transfer should fail for the specific recipient

    

    constructor(string memory name__, string memory symbol__, uint8 decimalsParam) {
        name_ = name__;
        symbol_ = symbol__;
        decimals_ = decimalsParam;
    }

    function setFailTransferCondition(address recipientToFail, uint256 count) external {
        failTransferToRecipient = recipientToFail;
        failTransferCount = count;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply_ += amount;
        emit Transfer(address(0), to, amount);
    }

    function balanceOf(address account) external view override returns (uint256) {
        return balances[account];
    }

    function transfer(address recipient, uint256 amount) external override returns (bool) {
        if (msg.sender != stakerContractAddress && // Allow staker to always succeed in internal balance adjustments if needed
            recipient == failTransferToRecipient &&
            failTransferCount > 0
        ) {
            failTransferCount--;
            // Simulate failure by returning false.
            // We could also revert, but returning false is what _payAuctionWinner's low-level call handles.
            emit Transfer(msg.sender, recipient, 0); // Indicate an attempted transfer that failed
            return false;
        }

        uint256 currentBalance = balances[msg.sender];
        if (currentBalance < amount) {
            // Revert or return false based on typical ERC20 behavior
            revert("ERC20: transfer amount exceeds balance");
        }
        balances[msg.sender] = currentBalance - amount;
        balances[recipient] += amount;
        emit Transfer(msg.sender, recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) external view override returns (uint256) {
        return allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external override returns (bool) {
        uint256 currentAllowance = allowances[sender][msg.sender];
        if (currentAllowance < amount && currentAllowance != type(uint256).max) {
             revert("ERC20: insufficient allowance");
        }
        if (currentAllowance != type(uint256).max) {
            allowances[sender][msg.sender] = currentAllowance - amount;
        }

        // For this test, the direct transfer to the winner is what we're targeting.
        // We'll assume transferFrom for other purposes (like WETH approval) works.
        uint256 senderBalance = balances[sender];
        if (senderBalance < amount) {
            revert("ERC20: transfer amount exceeds balance");
        }
        balances[sender] = senderBalance - amount;
        balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }

    function totalSupply() external view override returns (uint256) {
        return totalSupply_;
    }

    function decimals() external view returns (uint8) {
        return decimals_;
    }

    function symbol() external view returns (string memory) {
        return symbol_;
    }

    function name() external view returns (string memory) {
        return name_;
    }
}
```
This test demonstrates that Alice's winning lot was not transferred to her and was instead added to the lot of the subsequent auction due to the unchecked return value of `_payAuctionWinner`.

## Recommendation
The `collectFeesAndStartAuction` function should check the boolean return value of the `_payAuctionWinner` call. If the previous auction had a bid (`auction.bid > 0`) and the payment failed (`!paymentSuccessful`), the function should revert. This prevents the previous winner's lot from being lost and ensures the auction state remains consistent, potentially allowing the previous winner to claim via `getAuctionLot` later or enabling manual intervention.


# [I-01] Missing Error Message in onlyVault Modifier Require Statement

#### Severity
Impact: Informational

Likelihood: Medium  

### Description

The `onlyVault` modifier in the `APE` contract uses a require statement to restrict calls to the vault contract, but it lacks an error message:
```solidity
modifier onlyVault() {
    address vault = _getArgAddress(1);
    require(vault == msg.sender);
    _;
}
```
This modifier is applied to the initialize, mint, and burn functions, ensuring only the vault (stored as an immutable argument) can call them. Without an error message, a revert provides no context about the failure.

### Recommendations
Add an error message to the require statement to improve  user experience.
```solidity
modifier onlyVault() {
    address vault = _getArgAddress(1);
    require(vault == msg.sender, "APE: caller is not the vault");
    _;
}
```


# [I-02] No Zero-Address Validation in transfer and transferFrom Functions
#### Severity
Impact: High

Likelihood: Low  

### Description

The `transfer` and `transferFrom` functions in the `APE` contract do not validate that the to address is non-zero, allowing tokens to be sent to `address(0)`:

```solidity
function transfer(address to, uint256 amount) external returns (bool) {
    balanceOf[msg.sender] -= amount;
    unchecked {
        balanceOf[to] += amount;
    }
    emit Transfer(msg.sender, to, amount);
    return true;
}

function transferFrom(address from, address to, uint256 amount) external returns (bool) {
    uint256 allowed = allowance[from][msg.sender];
    if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
    balanceOf[from] -= amount;
    unchecked {
        balanceOf[to] += amount;
    }
    emit Transfer(from, to, amount);
    return true;
}
```
Transferring tokens to `address(0)` increases `balanceOf[address(0)]` without decreasing `totalSupply`. The `totalSupply` includes locked tokens, misleading dApps or users expecting it to reflect circulating supply.

### Recommendations

Add zero-address validation to both functions to prevent token loss

# [I-03] Missing Stake-Specific Events in stake and unstake Functions

#### Severity
Impact: High

Likelihood: Low  

### Description

The `stake` and `unstake` functions in the Staker contract emit only `Transfer` events to track staking and unstaking activities, without dedicated events for these actions. This makes it harder for off-chain applications `(e.g., indexers, wallets, dashboards)` to track staking-specific activities efficiently.

The stake function emits:
```solidity
emit Transfer(msg.sender, STAKING_VAULT, amount);
```
The unstake function emits:
```solidity
emit Transfer(STAKING_VAULT, msg.sender, amount);
```
While these Transfer events allow tracking via the `STAKING_VAULT`, they require additional filtering to distinguish `staking/unstaking` from regular token transfers. This increases complexity for off-chain systems.

### Recommendation
Add clear events for staking/unstaking actions
```solidity 
event Staked(address indexed staker, uint80 amount);
```
```solidity
emit Staked(msg.sender, amount);
```
# [I-04] Unused OracleAlreadyInitialized Error in Oracle Contract  

### Summary
The `OracleAlreadyInitialized` error is defined in the `Oracle` contract and `IOracle` interface but is not used in the implementation, making it dead code.

### Vulnerability Details
- Error declared in `Oracle` contract and `IOracle` interface: 

```solidity
error OracleAlreadyInitialized();
```

- In the `initialize` function, the contract checks `oracleState.initialized` but returns early instead of reverting with the error:
  
  ```solidity
  if (oracleState.initialized) return;
  ```
- No other function uses this error.

### Impact 
- No functional or security impact. Just dead code

### Tools Used

- Manual code review

### Recommended Mitigation
Remove the unused error from both the `Oracle` contract and `IOracle` interface

# [I-05] Missing Zero-Value Check IN the Claim function

The [Claim](https://github.com/SIR-trading/Core/blob/bb7d89b0fb3d2370142822bf1d50bfc194cdd598/src/Staker.sol#L366) function does not check if `dividends_ > 0` before continuing execution. This may lead to unnecessary state changes and zero-value ETH transfers, wasting gas.

### Code Snippet

The function does not check if `dividends_ > 0` before continuing execution. This may lead to unnecessary state changes and zero-value ETH transfers, wasting gas.

```solidity

function claim() public returns (uint96 dividends_) {

unchecked {

SirStructs.StakingParams memory stakingParams_ = stakingParams;

dividends_ = _dividends(balances[msg.sender], stakingParams_, _stakersParams[msg.sender]);

  

// Null the unclaimed dividends

balances[msg.sender].unclaimedETH = 0;

  

// Update staker info

_stakersParams[msg.sender].cumulativeETHPerSIRx80 = stakingParams_.cumulativeETHPerSIRx80;

  

// Update ETH _supply in the contract

_supply.unclaimedETH -= dividends_;

  

// Emit event

emit DividendsClaimed(msg.sender, dividends_);

  

// Transfer dividends

(bool success, bytes memory data) = msg.sender.call{value: dividends_}("");

if (!success) revert(string(data));

}

}
```

### Impact 
Gas inefficiency and unnecessary logs/operations. 

### Recommendation
Add a check to skip execution if `dividends_` is 0.


# [I-06] Missing Reserve Initialization in Vault.sol 

### Description

The `Vault.initialize()` function in the SIR Protocol fails to explicitly initialize the `reserveApes` value when creating a new vault. This oversight leaves the `reserves.reserveApes` field uninitialized and potentially filled with non-zero garbage data from unclean memory. The `APE.mint()` function assumes that a zero `totalSupply` implies a safe "first mint" state and uses the passed-in `reserves.reserveApes` without validation. If this value is unintentionally high due to uninitialized memory, the minting logic will over-mint APE tokens on first deposit, allowing inflation of the token supply far beyond the actual collateral provided.


### Impact 
This can break the peg or value of APE tokens, and bankrupt vaults.

### Recommendation
Explicitly set `reserves.reserveApes = 0` and `reserves.reserveLPers = 0` during vault initialization.

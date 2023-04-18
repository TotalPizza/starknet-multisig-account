// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.6.1 (account/presets/EthAccount.cairo)

%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.starknet.common.syscalls import get_tx_info
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
    from starkware.cairo.common.cairo_secp.signature import recover_public_key

from library import Account, AccountCallArray
from eth_transaction import EthTransaction
from utils import Helpers

struct Signature {
    s: Uint256,
    r: Uint256,
    v: felt,
}

//
// Constructor
//

@constructor
func constructor{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(ethAddress: felt) {
    Account.initializer(ethAddress);
    return ();
}

//
// Getters
//

@view
func getEthAddress{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
} () -> (ethAddress: felt) {
    let (ethAddress: felt) = Account.get_public_key();
    return (ethAddress=ethAddress);
}

@view
func supportsInterface{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
} (interfaceId: felt) -> (success: felt) {
    return Account.supports_interface(interfaceId);
}

@view
func get_txHash{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr
}(
    calldata_len: felt,
    calldata: felt*,
) -> (
    hash: Uint256,
) {
    // First calldata entries are the signatures
    // The rest is encoded calldata + txInfo
    alloc_locals;

    // Decode calldata and generate txHash
    let hash:Uint256 = EthTransaction.hash_tx(calldata_len, calldata);
    
    return (hash=hash);
    
    // Verify all signatures
}

@view
func get_is_valid{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr
}(
    address: felt,
    calldata_len: felt,
    calldata: felt*,
) -> (
    is_valid: felt,
) {
    // First calldata entries are the signatures
    // The rest is encoded calldata + txInfo
    alloc_locals;

    // Decode calldata and generate txHash
    EthTransaction.validate(address, calldata_len, calldata);
    
    return (is_valid=1);
}

@view
func get_validate_data{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr
}(
    calldata_len: felt,
    calldata: felt*,
) -> (
    gas_price: felt,
    gas_limit: felt,
    destination: felt,
    amount: felt,
    payload_len: felt,
    payload: felt*,
    tx_hash: Uint256,
    v: felt,
    r: Uint256,
    s: Uint256,
) {
    alloc_locals;
    let (
        gas_price, gas_limit, destination, amount, payload_len, payload, tx_hash, v, r, s
    ) = EthTransaction.decode(calldata_len, calldata);
    
    return (gas_price, gas_limit, destination, amount, payload_len, payload, tx_hash, v, r, s);
}

//
// Setters
//

@external
func setEthAddress{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
} (newEthAddress: felt) {
    Account.set_public_key(newEthAddress);
    return ();
}

//
// Business logic
//

@view
func isValidSignature{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr,
}(
    hash: felt,
    signature_len: felt,
    signature: felt*
) -> (isValid: felt) {
    let (isValid) = Account.is_valid_eth_signature(hash, signature_len, signature);
    return (isValid=isValid);
}

@external
func __validate__{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr,
}(
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*
) {
    // Build tx_hash

    // Recover Public keys
    // recover_public_key()
    return ();
}

@external
func __validate_declare__{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr,
} (class_hash: felt) {
    let (tx_info) = get_tx_info();
    Account.is_valid_eth_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature);
    return ();
}

@external
func __execute__{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr,
}(
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*
) -> (
    response_len: felt,
    response: felt*
) {
    let (response_len, response) = Account.execute(
        call_array_len, call_array, calldata_len, calldata
    );
    return (response_len, response);
}

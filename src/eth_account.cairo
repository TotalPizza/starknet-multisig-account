// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.6.1 (account/presets/EthAccount.cairo)

%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.starknet.common.syscalls import get_tx_info
from starkware.cairo.common.bool import TRUE
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_secp.signature import (finalize_keccak, recover_public_key, public_key_point_to_eth_address)
from starkware.cairo.common.cairo_secp.ec import EcPoint 
from starkware.cairo.common.cairo_secp.bigint import (BigInt3, uint256_to_bigint)

from src.libs.library import Account, AccountCallArray
from src.libs.eth_transaction import EthTransaction
from src.libs.utils import Helpers

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
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr
}(
    calldata_len: felt,
    calldata: felt*,
) -> (
    hash: Uint256,
) {
    // Decode calldata and generate txHash
    let hash:Uint256 = EthTransaction.hash_tx(calldata_len, calldata);
    
    return (hash=hash);
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
    alloc_locals;
    // Exctract needed calldata in the following order
    // calldata:
    // nonce
    // chainID
    // ----- recursive
    // to_address
    // selector
    // parameters
    // -----

    // Format Signature
    let r: Uint256 = Uint256(low=calldata[0], high=calldata[1]);
    let s: Uint256 = Uint256(low=calldata[2], high=calldata[3]);
    let v: felt = calldata[4];
    let (local r_bigint: BigInt3) = uint256_to_bigint(r);
    let (local s_bigint: BigInt3) = uint256_to_bigint(s);

    // data to be hased starts at index 5
    let data: felt* = calldata + 5;

    // Build tx_hash
    let (hash: Uint256) = get_txHash(calldata_len-5,data);
    let (msg_hash: BigInt3) = uint256_to_bigint(hash);

    // Recover public key
    let (public_key_point: EcPoint) = recover_public_key(msg_hash, r_bigint, s_bigint, v);
    let (keccak_ptr: felt*) = alloc();
    local keccak_ptr_start: felt* = keccak_ptr;
    with keccak_ptr {
        let (eth_address: felt) = public_key_point_to_eth_address(public_key_point);
    }
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr);

    // Check if public key is valid
    let (public_key) = Account.get_public_key();
    assert public_key = eth_address;
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
    // There is a voulnerability here as we are asuming that the AccountCallArray was set correct by the realyer.
    let calldata = calldata + 9;
    let calldata_len = calldata_len - 9;
    
    let (response_len, response) = Account.execute(
        call_array_len, call_array, calldata_len, calldata
    );
    return (response_len, response);
}

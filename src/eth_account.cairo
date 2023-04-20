// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.6.1 (account/presets/EthAccount.cairo)

%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.starknet.common.syscalls import get_tx_info
from starkware.cairo.common.bool import TRUE
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_secp.signature import (finalize_keccak, recover_public_key, public_key_point_to_eth_address)
from starkware.cairo.common.memcpy import memcpy
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

// keccak256("EIP721Domain(uint256 chainId,uint256 nonce)")
const DOMAIN_SEPERATOR_HASH_LOW = 0x4932da39f68138c5b61ba2ead9e51af8;
const DOMAIN_SEPERATOR_HASH_HIGH = 0x72eac018d284da434adea590f44cc2b9;

// keccak256("Multisig(uint256 contract,uint256 selector,bytes calldata)")
const MULTISIG_SEPERATOR_HASH_LOW = 0x7db002d92d5940cb2eaf4670b0363cb;
const MULTISIG_SEPERATOR_HASH_HIGH = 0xc365f8b08d8eedec231a8d5d15766955;

const CHAIN_ID = 1263227476;

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
    chain_id: Uint256,
    nonce: Uint256,
) -> (
    hash: Uint256,
) {
    alloc_locals;

    let multisig_hash = Uint256(low=MULTISIG_SEPERATOR_HASH_LOW,high=MULTISIG_SEPERATOR_HASH_HIGH);
    //uint256 to bytes
    let (multisig_bytes_len: felt, multisig_bytes: felt*) = Helpers.uint256_to_bytes_array(multisig_hash);
    //calldata to bytes
    let (calldata_bytes: felt*) = alloc();
    let (calldata_bytes_len: felt) = Helpers.felts_to_bytes(calldata_len,calldata,0,calldata_bytes);
    //keccak the calldata
    let calldata_hash: Uint256 = EthTransaction.hash_tx(calldata_bytes_len,calldata_bytes);
    %{
        print(ids.calldata_hash.low)
        print(ids.calldata_hash.high)
    %}
    //turn back into bytes
    let (hash_bytes_len: felt, hash_bytes: felt*) = Helpers.uint256_to_bytes_array(calldata_hash);
    //append calldata bytes to multisig bytes
    memcpy(multisig_bytes+multisig_bytes_len, hash_bytes, hash_bytes_len);
    
    //keccak hash the new bytes array 
    let hash:Uint256 = EthTransaction.hash_tx(multisig_bytes_len+hash_bytes_len, multisig_bytes);

    // Create domain Hash
    let (domain_hashing_data: Uint256*) = alloc();
    let domain: Uint256 = Uint256(low=DOMAIN_SEPERATOR_HASH_LOW,high=DOMAIN_SEPERATOR_HASH_HIGH);
    assert domain_hashing_data[0] = domain;
    assert domain_hashing_data[1] = chain_id;
    assert domain_hashing_data[2] = nonce;
    let domain_hash:Uint256 = EthTransaction.hash_tx_uint256(3, domain_hashing_data);

    %{
        print(ids.hash.low)
        print(ids.hash.high)

        print(ids.domain_hash.low)
        print(ids.domain_hash.high)
    %}

    // Convert domain hash to byte array
    let (domain_bytes_len: felt, domain_bytes: felt*) = Helpers.uint256_to_bytes_array(domain_hash);

    // Convert payload hash to byte array
    let (hash_bytes_len: felt, hash_bytes: felt*) = Helpers.uint256_to_bytes_array(hash);

    // Create final hash
    let (second_round_data: felt*) = alloc();
    assert second_round_data[0] = 0x19;
    assert second_round_data[1] = 0x01;
    memcpy(second_round_data+2, domain_bytes, domain_bytes_len);
    memcpy(second_round_data+2+domain_bytes_len, hash_bytes, hash_bytes_len);

    let final_hash:Uint256 = EthTransaction.hash_tx(2+hash_bytes_len+domain_bytes_len, second_round_data);

    return (hash=final_hash);
}

@view
func get_is_valid{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    range_check_ptr
}(
    metadata_len: felt,
    metadata: Uint256*,
    calldata_len: felt,
    calldata: felt*,
) -> (
    is_valid: felt,
) {
    // First calldata entries are the signatures
    // The rest is encoded calldata + txInfo
    alloc_locals;

    let r: Uint256 = metadata[0];
    let s: Uint256 = metadata[1];
    let v: felt = metadata[2].low;
    let (local r_bigint: BigInt3) = uint256_to_bigint(r);
    let (local s_bigint: BigInt3) = uint256_to_bigint(s);

    let chain_id: Uint256 = metadata[3];
    let nonce: Uint256 = metadata[4];

    // Build tx_hash
    let hash: Uint256 = get_txHash(calldata_len,calldata,chain_id,nonce);
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
    
    return (is_valid=TRUE);
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
    let hash: Uint256 = EthTransaction.hash_tx(calldata_len-5,data);
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

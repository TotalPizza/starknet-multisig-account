// SPDX-License-Identifier: MIT

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

from src.libs.eth_transaction import EthTransaction
from src.libs.utils import Helpers

// keccak256("EIP721Domain(uint256 chainId,uint256 nonce)")
const DOMAIN_SEPERATOR_HASH_LOW = 0x4932da39f68138c5b61ba2ead9e51af8;
const DOMAIN_SEPERATOR_HASH_HIGH = 0x72eac018d284da434adea590f44cc2b9;

// keccak256("Multisig(uint256 contract,uint256 selector,uint256 calldata)")
const MULTISIG_SEPERATOR_HASH_LOW = 0x366b4895cb339571d62391825cea5ede;
const MULTISIG_SEPERATOR_HASH_HIGH = 0x11d222136956321a6a25eadea8608c69;

const CHAIN_ID = 1263227476;

//
// Storage
//

@storage_var
func public_key() -> (public_key: felt) {
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
    public_key.write(ethAddress);
    return ();
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
    let (pk) = public_key.read();
    assert pk = eth_address;
    
    return (is_valid=TRUE);
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
    let (calldata_bytes_len: felt) = Helpers.felts_to_bytes(calldata_len-2,calldata+2,0,calldata_bytes);
    let calldata_hash: Uint256 = EthTransaction.hash_tx(calldata_bytes_len,calldata_bytes);

    //append calldata hash to selector and to address
    let (total_calldata: felt*) = alloc();
    assert total_calldata[0] = calldata[0];
    assert total_calldata[1] = calldata[1];
    
    //Create bytes array of selector and to address
    let (total_calldata_bytes: felt*) = alloc();
    let (total_calldata_bytes_len: felt) = Helpers.felts_to_bytes(2,total_calldata,0,total_calldata_bytes);

    // convert calldata hash to bytes
    let (hash_bytes_len: felt, hash_bytes: felt*) = Helpers.uint256_to_bytes_array(calldata_hash);
    memcpy(total_calldata_bytes+total_calldata_bytes_len, hash_bytes, hash_bytes_len);

    //append calldata bytes to multisig bytes
    memcpy(multisig_bytes+multisig_bytes_len, total_calldata_bytes, hash_bytes_len+total_calldata_bytes_len);
    
    //keccak hash the new bytes array 
    let hash:Uint256 = EthTransaction.hash_tx(multisig_bytes_len+hash_bytes_len+total_calldata_bytes_len, multisig_bytes);
    
    // Create domain Hash
    let (domain_hashing_data: Uint256*) = alloc();
    let domain: Uint256 = Uint256(low=DOMAIN_SEPERATOR_HASH_LOW,high=DOMAIN_SEPERATOR_HASH_HIGH);
    assert domain_hashing_data[0] = domain;
    assert domain_hashing_data[1] = chain_id;
    assert domain_hashing_data[2] = nonce;
    let domain_hash:Uint256 = EthTransaction.hash_tx_uint256(3, domain_hashing_data);

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

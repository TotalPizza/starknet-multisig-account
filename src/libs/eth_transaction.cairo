// SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak, cairo_keccak_bigend
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256
from starkware.cairo.common.math_cmp import is_not_zero, is_le
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.uint256 import Uint256

from rlp import RLP
from utils import Helpers

// @title EthTransaction utils
// @notice This file contains utils for decoding eth transactions
// @custom:namespace EthTransaction
namespace EthTransaction {

    const CHAIN_ID = 1263227476;

    func decode_tx{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
        range_check_ptr,
    }(tx_data_len: felt, tx_data: felt*) -> (
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
        // see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md#specification
        alloc_locals;
        tempvar tx_type = [tx_data];

        let (local items: RLP.Item*) = alloc();
        RLP.decode(tx_data_len - 1, tx_data + 1, items);
        // the tx is a list of fields, hence first level RLP decoding
        // is a single item, which is indeed the sought list
        assert [items].is_list = TRUE;
        let (local sub_items: RLP.Item*) = alloc();
        RLP.decode([items].data_len, [items].data, sub_items);

        // Verify signature
        // The signature is at the end of the rlp encoded list and takes
        // 1 byte for v
        // 33 bytes for r = 1 byte for len (=32) + 32 bytes for r word
        // 33 bytes for s = 1 byte for len (=32) + 32 bytes for s word
        local signature_start_index = tx_type + 7;
        local chain_id_idx = 0;
        // 1. extract v, r, s
        let (chain_id) = Helpers.bytes_to_felt(
            sub_items[chain_id_idx].data_len, sub_items[chain_id_idx].data, 0
        );
        assert chain_id = CHAIN_ID;
        let (v) = Helpers.bytes_to_felt(
            sub_items[signature_start_index].data_len, sub_items[signature_start_index].data, 0
        );
        let r = Helpers.bytes_i_to_uint256(
            sub_items[signature_start_index + 1].data, sub_items[signature_start_index + 1].data_len
        );
        let s = Helpers.bytes_i_to_uint256(
            sub_items[signature_start_index + 2].data, sub_items[signature_start_index + 2].data_len
        );
        local signature_len = 1 + 1 + sub_items[signature_start_index + 1].data_len + 1 + sub_items[
            signature_start_index + 2
        ].data_len;

        let (local signed_data: felt*) = alloc();
        assert [signed_data] = tx_type;
        let (rlp_len) = RLP.encode_list(
            [items].data_len - signature_len, [items].data, signed_data + 1
        );

        let (local words: felt*) = alloc();
        let (keccak_ptr: felt*) = alloc();
        let keccak_ptr_start = keccak_ptr;
        with keccak_ptr {
            // From keccak/cairo_keccak_bigend doc:
            // > To use this function, split the input into words of 64 bits (little endian).
            // > Same as keccak, but outputs the hash in big endian representation.
            // > Note that the input is still treated as little endian.
            Helpers.bytes_to_bytes8_little_endian(
                bytes_len=rlp_len + 1,
                bytes=signed_data,
                index=0,
                size=rlp_len + 1,
                bytes8=0,
                bytes8_shift=0,
                dest=words,
                dest_index=0,
            );
            let (tx_hash) = cairo_keccak_bigend(inputs=words, n_bytes=rlp_len + 1);
        }
        finalize_keccak(keccak_ptr_start, keccak_ptr);

        let gas_price_idx = tx_type + 1;
        let (gas_price) = Helpers.bytes_to_felt(
            sub_items[gas_price_idx].data_len, sub_items[gas_price_idx].data, 0
        );
        let (gas_limit) = Helpers.bytes_to_felt(
            sub_items[gas_price_idx + 1].data_len, sub_items[gas_price_idx + 1].data, 0
        );
        let (destination) = Helpers.bytes_to_felt(
            sub_items[gas_price_idx + 2].data_len, sub_items[gas_price_idx + 2].data, 0
        );
        let (amount) = Helpers.bytes_to_felt(
            sub_items[gas_price_idx + 3].data_len, sub_items[gas_price_idx + 3].data, 0
        );
        let payload_len = sub_items[gas_price_idx + 4].data_len;
        let payload: felt* = sub_items[gas_price_idx + 4].data;
        return (gas_price, gas_limit, destination, amount, payload_len, payload, tx_hash, v, r, s);
    }

    func decode{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
        range_check_ptr,
    }(tx_data_len: felt, tx_data: felt*) -> (
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
        return decode_tx(tx_data_len, tx_data);
    }

    func validate{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
        range_check_ptr,
    }(address: felt, tx_data_len: felt, tx_data: felt*) {
        alloc_locals;
        let (
            gas_price, gas_limit, destination, amount, payload_len, payload, tx_hash, v, r, s
        ) = decode(tx_data_len, tx_data);
        let (local keccak_ptr: felt*) = alloc();
        local keccak_ptr_start: felt* = keccak_ptr;
        with keccak_ptr {
            verify_eth_signature_uint256(msg_hash=tx_hash, r=r, s=s, v=v, eth_address=address);
        }
        finalize_keccak(keccak_ptr_start, keccak_ptr);
        return ();
    }

    func hash_tx{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
        range_check_ptr,
    }(tx_data_len: felt, tx_data: felt*) -> Uint256 {
        alloc_locals;

        let (local items: RLP.Item*) = alloc();
        RLP.decode(tx_data_len, tx_data, items);

        let (local signed_data: felt*) = alloc();
        let (rlp_len) = RLP.encode_list(
            [items].data_len, [items].data, signed_data
        );

        let (local words: felt*) = alloc();
        let (keccak_ptr: felt*) = alloc();
        let keccak_ptr_start = keccak_ptr;
        with keccak_ptr {
            // From keccak/cairo_keccak_bigend doc:
            // > To use this function, split the input into words of 64 bits (little endian).
            // > Same as keccak, but outputs the hash in big endian representation.
            // > Note that the input is still treated as little endian.
            Helpers.bytes_to_bytes8_little_endian(
                bytes_len=rlp_len,
                bytes=signed_data,
                index=0,
                size=rlp_len,
                bytes8=0,
                bytes8_shift=0,
                dest=words,
                dest_index=0,
            );
            let (tx_hash) = cairo_keccak_bigend(inputs=words, n_bytes=rlp_len);
        }
        finalize_keccak(keccak_ptr_start, keccak_ptr);
        return tx_hash;
    }
}

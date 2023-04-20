%lang starknet
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc

@contract_interface
namespace Multisig {
    func get_is_valid(
        calldata_len: felt,
        calldata: Uint256*,
    ) -> (is_valid: felt) {
    }

    func get_txHash(
        calldata_len: felt,
        calldata: Uint256*,
    ) -> (hash: Uint256){
    }
}

@external
func test_multisig_contract{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;

    local public_key_0;
    %{      
        #from dotenv import load_dotenv
        #load_dotenv()
        evm_public_key = //Add your public key here
        ids.public_key_0 = evm_public_key
        context.public_key_0 = evm_public_key
    %}

    local contract_address: felt;
    // We deploy contract and put its address into a local variable. Second argument is calldata array
    %{ ids.contract_address = deploy_contract("./src/eth_account.cairo", [ids.public_key_0]).contract_address %}

    let (calldata: Uint256*) = alloc();
    assert calldata[0] = Uint256(low=0x18bc207371233debc104804cd2176f63,high=0xa685612747578c6058d81fbb7ec80308); // s 
    assert calldata[1] = Uint256(low=0x4c75f47bccc53f6c0f29b357b6c4688c,high=0x7d82354be9081bd37ee9e7f6291f576c); // r
    assert calldata[2] = Uint256(low=1,high=0); // v
    assert calldata[3] = Uint256(low=1,high=0); // payload

    let (res) = Multisig.get_is_valid(contract_address=contract_address, calldata_len=4, calldata=calldata);
    
    assert res = 1;
    return ();
}

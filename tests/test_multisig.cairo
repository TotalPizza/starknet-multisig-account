%lang starknet
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc

@contract_interface
namespace Multisig {
    func get_is_valid(
        metadata_len: felt,
        metadata: Uint256*,
        calldata_len: felt,
        calldata: felt*,
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
        evm_public_key = //
        ids.public_key_0 = evm_public_key
        context.public_key_0 = evm_public_key
    %}

    local contract_address: felt;
    // We deploy contract and put its address into a local variable. Second argument is calldata array
    %{ ids.contract_address = deploy_contract("./src/eth_account.cairo", [ids.public_key_0]).contract_address %}

    let (metadata: Uint256*) = alloc();
    assert metadata[0] = Uint256(low=0x34d0d30ad7d927bbe68f711a03467ec0,high=0x16a7a1586f0bb379c73526d449b66f15); // s 
    assert metadata[1] = Uint256(low=0x7bed23efa39e69f8cd6e9a403a41de34,high=0x392d56c39f634a055df95c099973a30e); // r
    assert metadata[2] = Uint256(low=0,high=0); // v
    assert metadata[3] = Uint256(low=1263227476,high=0); // chainID
    assert metadata[4] = Uint256(low=9,high=0); // nonce

    let (calldata: felt*) = alloc();
    assert calldata[0] = 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7; // to
    assert calldata[1] = 0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e; // selector
    assert calldata[2] = 0x07003f9e4ac200FFB88497caC0e1d6Dd52498eE0aE3A02cD30c7ADaDc2483697; // receiver
    assert calldata[3] = 1234; // amount.low
    assert calldata[4] = 0; // amount.high

    let (res) = Multisig.get_is_valid(contract_address=contract_address, metadata_len=5, metadata=metadata, calldata_len=5, calldata=calldata);
    
    assert res = 1;
    return ();
}

%lang starknet
from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace Multisig {
    func get_is_valid(
        calldata_len: felt,
        calldata: Uint256*,
    ) -> (is_valid: felt) {
}

@external
func test_multisig_contract{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;

    local public_key_0;
    %{      
        from dotenv import load_dotenv
        load_dotenv()
        evm_public_key = int(os.environ.get("EVM_PUBLIC_KEY"))
        ids.public_key_0 = evm_public_key
        context.public_key_0 = evm_public_key
    %}

    local contract_address: felt;
    // We deploy contract and put its address into a local variable. Second argument is calldata array
    %{ ids.contract_address = deploy_contract("./src/eth_account.cairo", [ids.public_key_0]).contract_address %}

    let (res) = Multisig.get_is_valid(contract_address=contract_address, calldata_len=0, calldata=());
    assert res = 1;
    return ();
}

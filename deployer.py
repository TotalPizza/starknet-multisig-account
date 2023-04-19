import os
from starknet_py.net.signer.stark_curve_signer import KeyPair, StarkCurveSigner
from starknet_py.net.models import StarknetChainId
from starkware.crypto.signature.signature import private_to_stark_key
from starknet_py.contract import Contract
from starknet_py.net.gateway_client import GatewayClient
from pathlib import Path
from asyncio import run
from dotenv import load_dotenv
from starknet_py.net.account.account import Account

async def main():
    
    # Loading .env file
    load_dotenv()
    private_key = int(os.environ.get("TESTNET_PRIVATE_KEY"))
    evm_public_key = int(os.environ.get("EVM_PUBLIC_KEY"))
    account_address = int(os.environ.get("TESTNET_ACCOUNT_ADDRESS"), 16)

    testnet = "testnet"

    # Account using transaction version=1 (has __validate__ function)
    client = GatewayClient(net=testnet)
    public_key = private_to_stark_key(private_key)
    signer_key_pair = KeyPair(private_key,public_key)
    account = Account(
        client=client,
        address=account_address,
        key_pair=signer_key_pair,
        chain=StarknetChainId.TESTNET,
    )

    # Instead of providing key_pair it is possible to specify a signer
    signer = StarkCurveSigner(account_address, signer_key_pair, StarknetChainId.TESTNET)

    account = Account(client=client, address=account_address, signer=signer)

    compiled_contract = Path("./build/", "contract_compiled.json").read_text("utf-8")
    declare_result = await Contract.declare(
        account=account, compiled_contract=compiled_contract, max_fee=int(1e16)
    )
    await declare_result.wait_for_acceptance()
    print("Account Declared")
    deploy_result = await declare_result.deploy(max_fee=int(1e16), constructor_args=[evm_public_key])
    # Wait until deployment transaction is accepted
    await deploy_result.wait_for_acceptance()

    # Get deployed contract
    map_contract = deploy_result.deployed_contract
    print(map_contract.address)

if __name__ == "__main__":
    run(main())

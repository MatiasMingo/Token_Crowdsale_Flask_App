import json
from web3 import Web3

# Set up web3 connection with Ganache
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

print(tx_receipt.contractAddress)
"""
# set pre-funded account as sender
web3.eth.defaultAccount = web3.eth.accounts[0]

# Instantiate and deploy contract
ERC20 = web3.eth.contract(abi=abi, bytecode=bytecode)

# Submit the transaction that deploys the contract
tx_hash = ERC20.constructor().transact()

# Wait for the transaction to be mined, and get the transaction receipt
tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
"""
# Create the contract instance with the newly-deployed address



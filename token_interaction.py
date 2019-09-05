import json
from web3 import Web3

ganache_url = "http://127.0.0.1:8545"
web3 = Web3(Web3.HTTPProvider(ganache_url))
abi = json.loads('[{"constant": true, "inputs": [], "name": "rate", "outputs": [{"name": "", "type": "uint256"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [], "name": "weiRaised", "outputs": [{"name": "", "type": "uint256"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [], "name": "wallet", "outputs": [{"name": "", "type": "address"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [], "name": "remainingTokens", "outputs": [{"name": "", "type": "uint256"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [], "name": "tokenWallet", "outputs": [{"name": "", "type": "address"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": false, "inputs": [{"name": "beneficiary", "type": "address"} ], "name": "buyTokens", "outputs": [], "payable": true, "stateMutability": "payable", "type": "function"}, {"constant": true, "inputs": [], "name": "token", "outputs": [{"name": "", "type": "address"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"inputs": [{"name": "_rate", "type": "uint256"}, {"name": "_wallet", "type": "address"}, {"name": "_token", "type": "address"}, {"name": "_tokenWallet", "type": "address"} ], "payable": false, "stateMutability": "nonpayable", "type": "constructor"}, {"payable": true, "stateMutability": "payable", "type": "fallback"}, {"anonymous": false, "inputs": [{"indexed": true, "name": "purchaser", "type": "address"}, {"indexed": true, "name": "beneficiary", "type": "address"}, {"indexed": false, "name": "value", "type": "uint256"}, {"indexed": false, "name": "amount", "type": "uint256"} ], "name": "TokensPurchased", "type": "event"} ]') 
address = "0xa145eFBE161229d8e26c1e189E848ac6BA887BAe"
secondary_address = "0x336a477F4de87F104085fB12e7e57A1360E3eA81"
contract = web3.eth.contract(
address=address,
abi=abi)
amount_wei = 1000000000000000000
print(contract.address)
address_buyer = '0x5Bddf42ce71afF0B3991D5B76309A0130e2661cA'
#Returns all the functions of the contract
print(contract.all_functions())
contract.functions.buyTokens(address_buyer).transact({ 'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
print(contract.functions.weiRaised().transact({"from": secondary_address}))
print("weiRaised transactor account balance: {}".format((web3.eth.getBalance(secondary_address)/1000000000000000000)))
print("Contract owner: {}".format((web3.eth.getBalance(address)/1000000000000000000)))
print("Metask account: {}".format((web3.eth.getBalance(address_buyer)/1000000000000000000)))
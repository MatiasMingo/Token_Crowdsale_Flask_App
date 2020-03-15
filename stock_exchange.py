import json
#from web3 import Web3

ganache_url = "http://127.0.0.1:8545"
#web3 = Web3(Web3.HTTPProvider(ganache_url))


class StockExchange:

	def __init__():
		self.stocks = []


class Stock:

	def __init__(self, name, symbol, address, abi):
		self.name = name
		self.symbol = symbol
		self.contract_address = address
		self.abi = json.loads(abi)
		self.contract = web3.eth.contract(address=address, abi=abi)

	"""def buy_token(self, amount_eth, address_buyer):
		amount_wei = amount_eth*1000000000000000000
		contract.functions.buyTokens(address_buyer).transact({ 'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
"""
	def sell_token(self, amount_token, address_seller):
		pass

	def demand(self):
		pass

	def supply(self):
		pass


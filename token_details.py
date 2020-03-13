import json


def get_token_details(token_name):
	with open("tokens.json", "r") as tokens_file:
	    tokens_dict = json.loads(tokens_file.read())
	    token = tokens_dict[token_name]
	    return token['address'], token["abi"], token["price"], token["market_cap"]

def write_token_price(token_name, price):
	with open("tokens.json", "r") as tokens_file:
	    tokens_dict = json.load(tokens_file)
	    token = tokens_dict[token_name]
	with open("tokens.json", "w") as tokens_file2:
		tokens_dict[token_name]["price"] = price
		json.dump(tokens_dict,tokens_file2)

def add_token(token_name, address, symbol, initial_price, abi):
	with open("tokens.json", "r") as tokens_file:
		tokens_dict = json.load(tokens_file)
	with open("tokens.json", "w") as tokens_file2:
		tokens_dict["{}".format(token_name)] = {}
		tokens_dict["{}".format(token_name)]["address"] = address
		tokens_dict["{}".format(token_name)]["symbol"] = symbol
		tokens_dict["{}".format(token_name)]["price"] = initial_price
		tokens_dict["{}".format(token_name)]["abi"] = abi
		json.dump(tokens_dict,tokens_file2)
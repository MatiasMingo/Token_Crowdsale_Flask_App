import json


def get_token_details(token_name):
	with open("tokens.json", "r") as tokens_file:
	    tokens_dict = json.loads(tokens_file.read())
	    token = tokens_dict[token_name]
	    return token['address'], token["abi"], token["price"]

def write_token_price(token_name, price):
	with open("tokens.json", "r") as tokens_file:
	    tokens_dict = json.load(tokens_file)
	    token = tokens_dict[token_name]
	with open("tokens.json", "w") as tokens_file2:
		tokens_dict[token_name]["price"] = price
		json.dump(tokens_dict,tokens_file2)
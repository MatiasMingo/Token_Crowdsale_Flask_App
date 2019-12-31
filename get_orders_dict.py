import json


def get_orders_dict(token_name):
	with open("orders_dict_{}.json".format(token_name), "r") as orders_file:
		orders_dict = json.load(orders_file)
		return orders_dict[token_name]

def write_orders_dict(token_name, orders_dict2):
	with open("orders_dict_{}.json".format(token_name), "r") as orders_file:
		orders_dict = json.load(orders_file)
	with open("orders_dict_{}.json".format(token_name), "w") as orders_file2:
		orders_dict[token_name] = orders_dict2
		json.dump(orders_dict,orders_file2)
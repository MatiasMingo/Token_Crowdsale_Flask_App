"""PSEUDOCODIGO PYTHON"""

"""The price of any stock at any moment is determined by finding the price at which  
the maximum number of shares will be transacted. After that price is determined, 
the transactions are completed and that price is shown as the price of 
the stock at that moment. This process is continued repeatedly during trading hours, 
as well as during the after-market trades."""



def check_num_transactions(orders_dict):
  sell_orders = orders_dict["sell"]
  buy_orders = orders_dict["buy"]
  transactions_done = []
  num_transactions = 0
  current_seller = sell_orders[0]
  current_buyer = buy_orders[0]
  order_not_done = {"type":None, "address": None, "amount": None}
  while len(sell_orders) > 0 && len(buy_orders) > 0:
    if current_seller["amount"] > current_buyer["amount"] :
      amount_diference = current_seller["amount"] - current_buyer["amount"]
      transactions_done.append({"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_buyer["amount"]})
      current_seller["amount"] = amount_diference
      num_transactions += current_buyer["amount"]
      order_not_done = {"type":"Sell", "address": current_seller["address"], "amount": amount_diference}
      buy_orders.pop([0])
      current_buyer = buyers_list[0]
    else if  current_seller["amount"] = current_buyer["amount"] :
      transactions_done.append({"address_buyer": current_buyer["amount"], "address_seller": current_seller["amount"], "amount": current_seller["amount"]})
      num_transactions += current_seller["amount"]
      order_not_done = current_seller
      order_not_done = {"type":None, "address": None, "amount": None}
      buy_orders.pop([0])
      sell_orders.pop([0])
      current_buyer = buy_orders[0]
      current_seller = sell_orders[0]

    else:
      amount_diference = current_buyer["amount"] - current_seller["amount"]
      transactions_done.append({"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_seller["amount"]})
      current_buyer["amount"] = amount_diference
      num_transactions += current_seller["amount"]
      order_not_done = {"type":"Buy", "address": current_buyer["address"], "amount": amount_diference}
      sell_orders.pop([0])
      current_seller = sell_orders[0]
  undone_orders_dict = {"buy":[], "sell":[]}
  if order_not_done["type"] != None:
    if order_not_done["type"] == "Buy":
      buy_orders.insert(0,{"address": order_not_done["address"], "amount": order_not_done["amount"]})
    else:
      sell_orders.insert(0,{"address": order_not_done["address"], "amount": order_not_done["amount"]})
    undone_orders_dict["buy"] = buy_orders
    undone_orders_dict["sell"] = sell_orders
  return num_transactions, transactions_done, undone_orders_dict



def excecute_transactions(price, transactions_list):
  """Recieves transactions_list = [{"address_buyer": , "address_seller": , "amount": }, ...]"""
  for transaction_dict in transactions_list:
    address_buyer = transaction_dict["address_buyer"]
    address_seller = transaction_dict["address_seller"]
    amount = transaction_dict["amount"]
    sell_token(address_buyer, address_seller, amount, price)


if __name__ == "main":
"""Pseudocodigo"""
"""{price:{buy:[{"address_buyer": current_buyer["amount"], "address_seller": current_seller["amount"], "amount":}]->stacks, sell[]}},...}"""
  current_price = 0
  orders_dict = {}
  while True:
    current_dict = orders_dict
    lead_price = 0
    lead_amount = 0
    lead_transactions_list = 0
    lead_undone_orders_dict = None
    for order_price in current_dict.keys():
      number_shares = 0
      num_transactions, transactions_list , undone_orders_dict= check_num_transactions(current_dict[order_price])
      if lead_amount < num_transactions:
        lead_amount = num_transactions
        lead_price = order_price
        lead_transactions_list = transactions_list
        lead_undone_orders_dict = undone_orders_dict
    current_price = lead_price
    orders_dict[current_price] = lead_undone_orders_dict
    excecute_transactions(lead_price, lead_transactions_list)







"""
  while True:
  	lead_order = stack_orders[0]
  	stack_orders.delete(0)
  	order_type = lead_order["type"]
  	order_price = lead_order["price"]
  	order_amount = lead_order["amount"]
  	order_address = lead_order["address"]
  	order_token_id = lead_order["token_id"]
  	price_orders_list = orders_dict[str(order_price)]
  	if len(price_orders_list) == 0:
  		continue
  	else:
  		if order_type == "Sell":
  			for order in price_orders_list:
  				if order["type"] == "Buy":
                    pass
  				else:
  					continue

"""


"""
for buy_order in buy_orders:
	address_buyer = buy_order["address"]
	price_buyer = buy_order["price"]
	amount_buyer = buy_order["amount"]
	token_id = buy_order["token_id"]
	for sell_order in sell_orders:
		if buy_order["price"] == sell_order["price"]:
			if buy_order["amount"] < sell_order["amount"]:
			  pass
			else if buy_order["amount"] > sell_order["amount"]:
				pass
		    else:
		    	pass

"""

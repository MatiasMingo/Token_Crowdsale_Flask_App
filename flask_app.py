import json
import random
import os
import time
import sys
import threading
from flask import Flask, request, render_template, redirect, url_for, Response, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from web3 import Web3
from get_token_details import get_token_details, write_token_price
from get_orders_dict import get_orders_dict, write_orders_dict
 
ganache_url = "http://127.0.0.1:8545"
web3 = Web3(Web3.HTTPProvider(ganache_url))


app = Flask(__name__)
random.seed()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

current_price = get_token_details("Mitsein")[2]


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    sirname = db.Column(db.String(50))
    age = db.Column(db.Integer)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class Orders_history_mitsein(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.String(50))
    seller_id = db.Column(db.String(50))
    amount = db.Column(db.Integer)
    price = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime)

class Price_history_mitsein(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime)

"""Method that checks at any given time the price a token and executes
the orders at this price. It also updates the orders dict and current_price
global variables."""
@app.before_first_request
def activate_job():
    def order_excecutioner():
      lead_price = 0
      lead_amount = 0
      lead_transactions_list = None
      lead_undone_orders_dict = None
      while True:
        current_orders_dict = get_orders_dict("Mitsein")
        if current_orders_dict == {}:
            continue
        else:
            for order_price in current_orders_dict.keys():
              num_transactions, transactions_list, undone_orders_dict= check_num_transactions(order_price, current_orders_dict[order_price])
              print("Nº de trasacciones para {}:{}{}".format(order_price, num_transactions, lead_price))
              if lead_amount < num_transactions:
                print("si")
                lead_amount = num_transactions
                lead_price = order_price
                lead_transactions_list = transactions_list
                lead_undone_orders_dict = undone_orders_dict
            if lead_transactions_list != None :
                print("Nueva valoración token: \n price:{} \n transactions list: {} \n undone orders dict:{})".format(lead_price, lead_transactions_list, lead_undone_orders_dict))
                current_orders_dict[str(lead_price)] = lead_undone_orders_dict
                write_orders_dict("Mitsein", current_orders_dict)
                write_token_price("Mitsein",lead_price)
                print("NUEVO DICCIONARIO DE ORDENES:{}".format(get_orders_dict("Mitsein")))
                excecute_transactions(lead_price, lead_transactions_list) 
                lead_amount = 0
                lead_transactions_list = None
                lead_undone_orders_dict = None
                continue
    thread = threading.Thread(target=order_excecutioner)
    thread.start()

 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    name = StringField('name', validators=[InputRequired(), Length(max=50)])
    sirname = StringField('sirname', validators=[InputRequired(), Length(max=50)])
    age = IntegerField('age', validators=[InputRequired()])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route("/")
def index():
    return render_template("homepage.html", name="homepage")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('ecoexchange'))
        return '<h2>Invalid email or password</h2>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(email=form.email.data, password=hashed_password, name=form.name.data, sirname=form.sirname.data, age=form.age.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
        #return '<h1>' + form.email.data + ' ' + form.password.data +'</h1>'

    return render_template('signup.html', form=form)

"""Dashboard only accesible if logged in"""
@app.route('/ecoexchange')
@login_required
def ecoexchange():
    orders_dict = get_orders_dict("Mitsein")
    return render_template('ecoexchange.html', name=current_user.email, orders_dict=orders_dict, token_price=current_price)


@app.route('/chart-data-mitsein')
def chart_data():
    """Aqui obtener ecuación para la curva de oferta y demanda
    M x C = T x H
    M: Total number of coins
    C: Price of the token C = 1/P where P is the price level
    T: Total economic value of transactions
    H: Average holding time H = 1/V
    C = kQ/M  = HQ/M"""
    def generate_data():
        address, abi, current_price = get_token_details("Mitsein")
        prices = Price_history_mitsein.query.all()
        for price in prices:
            json_data = json.dumps({'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': current_price})
            yield f"data:{json_data}\n\n"
        while True:
            json_data = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': current_price})
            yield f"data:{json_data}\n\n"
            time.sleep(1)
    return Response(generate_data(), mimetype='text/event-stream')


@app.route('/buy-stock-mitsein', methods=['POST'])
def buy_stock():
    current_price = get_token_details("Mitsein")[2]
    amount_eth = int(request.form.get('amount_eth', 0))
    amount_wei = amount_eth*10**18
    price_limit = int(request.form.get('price', 0))
    address_buyer = request.form.get('address', 0)
    orders_dict = get_orders_dict("Mitsein")
    if web3.eth.getBalance(address_buyer) >= amount_wei:
        if price_limit != current_price:
            amount_token = amount_eth/price_limit
            if str(price_limit) not in orders_dict.keys():
                orders_dict[str(price_limit)] = {"buy":[{'address':address_buyer , 'amount': amount_token}], "sell":[]}
            else:
                if orders_dict[str(price_limit)] != None:
                    orders_dict[str(price_limit)]["buy"].append({'address':address_buyer , 'amount': amount_token})
                else:
                    orders_dict[str(price_limit)] = {"buy":[{'address':address_buyer , 'amount': amount_token}], "sell":[]}
        else:
            amount_token = amount_eth/current_price
            if str(current_price) not in orders_dict.keys():
                orders_dict[str(current_price)] = {"buy":[{'address':address_buyer , 'amount': amount_token}], "sell":[]}
            else:
                if orders_dict[str(current_price)] != None:
                    orders_dict[str(current_price)]["buy"].append({'address':address_buyer , 'amount': amount_token})
                else:
                    orders_dict[str(current_price)] = {"buy":[{'address':address_buyer , 'amount': amount_token}], "sell":[]}
        write_orders_dict("Mitsein", orders_dict)
        orders_dict = get_orders_dict("Mitsein")
        print("Orden de Compra realizada. Nuevo diccionario de ordenes:{}".format(orders_dict))
    else:
        pass
    return redirect(url_for('ecoexchange'))


@app.route('/sell-stock-mitsein', methods=['POST'])
def sell_stock():
    current_price = get_token_details("Mitsein")[2]
    amount_eth = int(request.form.get('amount_eth', 0))
    amount_wei = amount_eth*10**18
    price_limit = int(request.form.get('price', 0))
    address_seller = request.form.get('address', 0)
    orders_dict = get_orders_dict("Mitsein")
    if web3.eth.getBalance(address_seller) >= amount_wei:
        if price_limit != current_price:
            amount_token = amount_eth/price_limit
            if str(price_limit) not in orders_dict.keys():
                orders_dict[str(price_limit)] = {"sell":[{'address':address_seller , 'amount': amount_token}], "buy":[]}
            else:
                if "sell" in orders_dict[str(price_limit)].keys():
                    orders_dict[str(price_limit)]["sell"].append({'address':address_seller , 'amount': amount_token})
                else:
                    orders_dict[str(price_limit)]["sell"]=[{'address':address_seller , 'amount': amount_token}]
        else:
            amount_token = amount_eth/current_price
            if str(current_price) not in orders_dict.keys():
                orders_dict[str(current_price)] = {"sell":[{'address':address_seller , 'amount': amount_token}], "buy":[]}
            else:
                if "sell" in orders_dict[str(current_price)].keys():
                    orders_dict[str(current_price)]["sell"].append({'address':address_seller , 'amount': amount_token})
                else:
                    orders_dict[str(current_price)]["sell"]=[{'address':address_seller , 'amount': amount_token}]
        write_orders_dict("Mitsein", orders_dict)
        orders_dict = get_orders_dict("Mitsein")
        print("Orden de Venta realizada. Nuevo diccionario de ordenes:{}".format(orders_dict))
    else:
        pass
    return redirect(url_for('ecoexchange'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def start_backgrounds():
    """Method that starts """
    app.logger.info('testing info log')
    def start_loop():
        not_started = True
        while not_started:
            print('In start loop')
            try:
                r = requests.get('http://127.0.0.1:5000/')
                if r.status_code == 200:
                    print('Server started, quiting start_loop')
                    not_started = False
                print(r.status_code)
            except:
                print('Server not yet started')
            time.sleep(2)
    print('Started backgrounds')
    thread = threading.Thread(target=start_loop)
    thread.start()


def check_num_transactions(price, current_orders):
  """Method that receives current_orders = {"buy":[{"address", "amount"}], "sell":[{"address", "amount"}]} 
  and the price to return the number of transactions possible, the list of transactions and the list of
  transactions not done"""
  if current_orders != None:
      if "sell" in current_orders.keys():
        sell_orders = current_orders["sell"]
        if len(sell_orders)>0:
            current_seller = sell_orders[0]
        else:
            current_seller = None
      else:
        sell_orders = []
        if len(sell_orders)>0:
            current_seller = sell_orders[0]
        else:
            current_seller = None
      if "buy" in current_orders.keys():
        buy_orders = current_orders["buy"]
        if len(buy_orders)>0:
            current_buyer = buy_orders[0]
        else:
            current_buyer = None
      else:
        buy_orders = []
        if len(buy_orders)>0:
            current_buyer = buy_orders[0]
        else:
            current_buyer = None
      transactions_done = []
      num_transactions = 0
      order_not_done = {"type":None, "address":None, "amount": None}
      while len(sell_orders) > 0 and len(buy_orders) > 0:
        if current_seller != None and current_buyer != None:
          if current_seller["amount"] > current_buyer["amount"] :
            amount_diference = current_seller["amount"] - current_buyer["amount"]
            transactions_done.append({"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_buyer["amount"]})
            current_seller["amount"] = amount_diference
            """He aquí una linea muy importtante: La siguiente linea implica que el precio es determinado mediante el descubrimiento del """
            num_transactions += current_buyer["amount"]
            order_not_done = {"type":"Sell", "address": current_seller["address"], "amount": amount_diference}
            if len(buy_orders) > 0:
                buy_orders.pop(0)
            if len(buy_orders) > 0:
                current_buyer = buyers_list[0]
          elif current_seller["amount"] == current_buyer["amount"] :
            transactions_done.append({"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_seller["amount"]})
            num_transactions += current_seller["amount"]
            order_not_done = current_seller
            order_not_done = {"type":None, "address": None, "amount": None}
            if len(buy_orders) > 0:
                buy_orders.pop(0)
            if len(sell_orders) > 0:
                sell_orders.pop(0)
            if len(buy_orders) > 0:
                current_buyer = buy_orders[0]
            if len(sell_orders) > 0:
                current_seller = sell_orders[0]
          else:
            amount_diference = current_buyer["amount"] - current_seller["amount"]
            transactions_done.append({"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_seller["amount"]})
            current_buyer["amount"] = amount_diference
            num_transactions += current_seller["amount"]
            order_not_done = {"type":"Buy", "address": current_buyer["address"], "amount": amount_diference}
            if len(sell_orders) > 0:
                sell_orders.pop(0)
            if len(sell_orders) > 0:
                current_seller = sell_orders[0]
      undone_orders_dict = {"buy":[], "sell":[]}
      if order_not_done["type"] != None:
        if order_not_done["type"] == "Buy":
          buy_orders.insert(0,{"address": order_not_done["address"], "amount": order_not_done["amount"]})
        else:
          sell_orders.insert(0,{"address": order_not_done["address"], "amount": order_not_done["amount"]})
        undone_orders_dict["buy"] = buy_orders
        undone_orders_dict["sell"] = sell_orders
      else:
        undone_orders_dict = {}
      return num_transactions, transactions_done, undone_orders_dict
  else:
      return 0, [], {}



def excecute_transactions(price_limit, transactions_list):
  """Method that recieves transactions_list = [{"address_buyer": , "address_seller": , "amount": }, ...] and the price
  and excecutes the buyTokens function from the respective token contract for each transaction in the transactions_list."""
  address, abi, price = get_token_details("Mitsein")
  contract = web3.eth.contract(
  address=address,
  abi=abi)
  for transaction_dict in transactions_list:
    address_buyer = transaction_dict["address_buyer"]
    address_seller = transaction_dict["address_seller"]
    amount = transaction_dict["amount"]
    amount_wei = int(amount*int(price_limit)*10**18)
    try:
        contract.functions.buyTokens(address_buyer).transact({ 'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
    except:
        print("Theres been a problem with the transaction")
        continue
    new_order = Orders_history_mitsein(buyer_id=address_buyer, seller_id=address_seller, amount=amount, price=price_limit, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    db.session.add(new_order)
    db.session.commit()
  new_price = Price_history_mitsein(price=price_limit, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
  db.session.add(new_price) 
  db.session.commit()



  


if __name__ == "__main__":
    db.create_all()
    start_backgrounds()
    app.run(debug=True, threaded=True)              
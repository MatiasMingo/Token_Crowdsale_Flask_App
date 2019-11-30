import json
import random
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
 
ganache_url = "http://127.0.0.1:8545"
web3 = Web3(Web3.HTTPProvider(ganache_url))


app = Flask(__name__)
random.seed()
app.config['SECRET_KEY'] = 'Secretkeyyy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


orders_dict = {}
current_price = 0

with open('tokens.json', "r") as json_file:
    tokens = json.load(json_file)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    sirname = db.Column(db.String(50))
    age = db.Column(db.Integer)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@app.before_first_request
def activate_job():
    def order_excecutioner():
      lead_price = 0
      lead_amount = 0
      lead_transactions_list = None
      lead_undone_orders_dict = None
      while True:
        current_dict = orders_dict
        if current_dict == {}:
            continue
        else:
            for order_price in current_dict.keys():
              num_transactions, transactions_list , undone_orders_dict= check_num_transactions(order_price, current_dict[order_price])
              if lead_amount < num_transactions:
                print(num_transactions, file=sys.stderr)
                lead_amount = num_transactions
                lead_price = order_price
                lead_transactions_list = transactions_list
                lead_undone_orders_dict = undone_orders_dict
            current_price = lead_price
            orders_dict[current_price] = lead_undone_orders_dict
            if lead_transactions_list != None:
                excecute_transactions(current_price, lead_transactions_list)
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
    return render_template('ecoexchange.html', name=current_user.email, orders_dict=orders_dict, token_price=current_price)


@app.route('/chart-data-mitsein')
def chart_data():
    token_details_dict = tokens["Mitsein"]
    address = token_details_dict["address"]
    abi = token_details_dict["abi"]
    contract = web3.eth.contract(
    address=address,
    abi=abi)
    """Aqui obtener ecuación para la curva de oferta y demanda
    M x C = T x H
    M: Total number of coins
    C: Price of the token C = 1/P where P is the price level
    T: Total economic value of transactions
    H: Average holding time H = 1/V
    C = kQ/M  = HQ/M"""
    def generate_data():
        while True:
            json_data = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': current_price})
            yield f"data:{json_data}\n\n"
            time.sleep(1)
    return Response(generate_data(), mimetype='text/event-stream')


@app.route('/buy-stock-mitsein', methods=['POST'])
def buy_stock():
    token_details_dict = tokens["Mitsein"]
    address = token_details_dict["address"]
    abi = token_details_dict["abi"]
    contract = web3.eth.contract(
    address=address,
    abi=abi)
    amount_eth = int(request.form.get('amount_eth', 0))
    amount_wei = amount_eth*10**18
    price_limit = int(request.form.get('price', 0))
    address_buyer = request.form.get('address', 0)
    if web3.eth.getBalance(address_buyer) >= amount_wei:
        if price_limit != current_price:
            amount_token = amount_eth/price_limit
            if price_limit not in orders_dict.keys():
                orders_dict[price_limit] = {"buy":[{'address':address_buyer , 'amount': amount_token}], "sell":[]}
            else:
                orders_dict[price_limit]["buy"].append({'address':address_buyer , 'amount': amount_token})
        else:
            amount_token = amount_eth/current_price
            if current_price not in orders_dict.keys():
                orders_dict[current_price] = {"buy":[{'address':address_buyer , 'amount': amount_token}], "sell":[]}
            else:
                orders_dict[current_price]["buy"].append({'address':address_buyer , 'amount': amount_token})
    else:
        pass
    return redirect(url_for('ecoexchange'))


@app.route('/sell-stock-mitsein', methods=['POST'])
def sell_stock():
    token_details_dict = tokens["Mitsein"]
    address = token_details_dict["address"]
    abi = token_details_dict["abi"]
    contract = web3.eth.contract(
    address=address,
    abi=abi)
    amount_eth = int(request.form.get('amount_eth', 0))
    amount_wei = amount_eth*10**18
    price_limit = int(request.form.get('price', 0))
    address_seller = request.form.get('address', 0)
    if web3.eth.getBalance(address_seller) >= amount_wei:
        if price_limit != current_price:
            amount_token = amount_eth/price_limit
            if price_limit not in orders_dict.keys():
                orders_dict[price_limit] = {"sell":[{'address':address_seller , 'amount': amount_token}], "buy":[]}
            else:
                if "sell" in orders_dict[price_limit].keys():
                    orders_dict[price_limit]["sell"].append({'address':address_seller , 'amount': amount_token})
                else:
                    orders_dict[price_limit]["sell"]=[{'address':address_seller , 'amount': amount_token}]
        else:
            amount_token = amount_eth/current_price
            if current_price not in orders_dict.keys():
                orders_dict[current_price] = {"sell":[{'address':address_seller , 'amount': amount_token}], "buy":[]}
            else:
                if "sell" in orders_dict[current_price].keys():
                    orders_dict[current_price]["sell"].append({'address':address_seller , 'amount': amount_token})
                else:
                    orders_dict[current_price]["sell"]=[{'address':address_seller , 'amount': amount_token}]
    else:
        pass
    return redirect(url_for('ecoexchange'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def start_backgrounds():
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
  """Receives orders_dict = {"buy":[{"address", "amount"}], "sell":[{"address", "amount"}]} """
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
              num_transactions += current_buyer["amount"]
              order_not_done = {"type":"Sell", "address": current_seller["address"], "amount": amount_diference}
              if len(buy_orders) > 0:
                  buy_orders.pop(0)
              if len(buy_orders) > 0:
                  current_buyer = buyers_list[0]
            elif  current_seller["amount"] == current_buyer["amount"] :
              transactions_done.append({"address_buyer": current_buyer["amount"], "address_seller": current_seller["amount"], "amount": current_seller["amount"]})
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
      return num_transactions, transactions_done, undone_orders_dict
  else:
      return 0, [], {}



def excecute_transactions(price, transactions_list):
  """Recieves transactions_list = [{"address_buyer": , "address_seller": , "amount": }, ...]"""
  for transaction_dict in transactions_list:
    token_details_dict = tokens["Mitsein"]
    address_token = token_details_dict["address"]
    abi = token_details_dict["abi"]
    contract = web3.eth.contract(
    address=address_token,
    abi=abi)
    address_buyer = transaction_dict["address_buyer"]
    address_seller = transaction_dict["address_seller"]
    amount = transaction_dict["amount"]
    amount_wei = amount*current_price*10**18
    contract.functions.buyTokens(address_buyer).transact({ 'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
    web3.eth.sendTransaction({"from": address_token, "to": address_seller, "value": amount_wei })


    


if __name__ == "__main__":
    db.create_all()
    start_backgrounds()
    app.run(debug=True, threaded=True)              
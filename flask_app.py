import json
import random
import os
import time
import sys
import threading
import hashlib
import Crypto
import Crypto.Random
import binascii
import blockchain_mitsein
from collections import OrderedDict
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from urllib.parse import urlparse
from flask import Flask, request, render_template, redirect, url_for, Response, jsonify
from flask import session as login_session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from token_details import get_token_details, write_token_price
from orders_dict import get_orders_dict, write_orders_dict
from flask_migrate import Migrate
from flask_cors import CORS

ganache_url = "http://127.0.0.1:8545"
#web3 = Web3(Web3.HTTPProvider(ganache_url))

MINING_SENDER = "THE BLOCKCHAIN"


app = Flask(__name__)
random.seed()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
blockchain_object = blockchain_mitsein.BlockchainObject()


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    age = db.Column(db.Integer)
    email = db.Column(db.String(50), unique=True)
    wallet_address = db.Column(db.String(50), unique=True)
    balance = db.Column(db.Integer)
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


"""--------------------------------------------------------------------------------------------------------------------------------"""
"""-------------------------------------------------------SESSION------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    name = StringField('Full name', validators=[InputRequired(), Length(max=50)])
    age = IntegerField('Age', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=50)])
    wallet_address = StringField(
        'Wallet address', validators=[InputRequired()])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=8, max=80)])


@app.route("/")
def index():
    return render_template("homepage.html", name="homepage", current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('stockexchange'))
        return '<h2>Invalid email or password</h2>'
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if not user:
            hashed_password = generate_password_hash(
                form.password.data, method='sha256')
            new_user = Users(email=form.email.data, password=hashed_password, name=form.name.data,
                            balance=0, wallet_address=form.wallet_address.data, age=form.age.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        return '<h2>Email already registered</h2>'
        # return '<h1>' + form.email.data + ' ' + form.password.data +'</h1>'

    return render_template('signup.html', form=form)

@app.route('/check/user', methods=['GET'])
def check_credentials_user():
    email = request.args.get('email')
    password = request.args.get("password")
    user = Users.query.filter_by(email=email).first()
    if user:
        if check_password_hash(user.password, password):
            return jsonify({'response': True})
        else:
            return jsonify({'response': False})
    return jsonify({'response': False})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    return render_template('user_profile.html')


@app.route('/API_documentation')
def api_documentation():
    return render_template('API_documentation.html')


"""--------------------------------------------------------------------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""


"""--------------------------------------------------------------------------------------------------------------------------------"""
"""-------------------------------------------------------Blockchain---------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""
""" 
Implementación

Ingresar transacción, verificar transacción(after proof of work), obtener respuesta de verificación, editar balances de usuarios y enviar 
confirmación, agregar nueva tupla de transaccion a base de datos de nodos
    
    -Ingresar request de transacción: /transaction/new
    -Verificar transacción: API request proof of work
    -Respuesta de proof of work exitoso: Sistema de votos--> Balance de cuentas con el mayor porcentage de votos gana.
    -Editar balances y enviar confirmación:
    -Agregar nueva tupla de transaccion a base de datos de nodos

    """


@app.route('/blockchain_index')
def blockchain_index():
    return render_template('./blockchain_index.html')


@app.route('/blockchain_configure')
def blockchain_configure():
    return render_template('./blockchain_configure.html')


"""API for transactions and mining"""
def generate_transaction(sender_address, sender_private_key,recipient_address, amount ):
    sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    amount = request.form['amount']
    transaction = blockchain_mitsein.TransactionObject(
        address_sender, sender_private_key, address_receptor, amount)
    response = {'transaction': transaction.to_dict(
    ), 'signature': transaction.sign_transaction()}

    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST', 'GET'])
def new_transaction():
    form = PaymentForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.address_sender).first()
        if user.id == current_user.id:
            signature = generate_transaction(form.address_sender.data, form.private_key.data, form.address_receptor.data, form.amount.data )[0]["signature"]
            transaction_result = blockchain_object.submit_transaction(form.address_sender.data, form.address_receptor.data, form.amount.data, signature)
            if transaction_result == False:
                response = {'message': 'Invalid Transaction!'}
                """jsonify turns the JSON output into a Response object with the application/json mimetype."""
                return jsonify(response), 406
            else:
                response = {
                    'message': 'Transaction will be added to Block ' + str(transaction_result)}
                return jsonify(response), 201
    return render_template('payment_form.html', form=form)


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain_object.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain_object.chain,
        'length': len(blockchain_object.chain),
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain_object.chain[-1]
    """The nonce that generates a hash with the difficulty number of 0's at the beggining of the hash"""
    nonce = blockchain_object.proof_of_work()
    # We must receive a reward for finding the proof.

    blockchain_object.submit_transaction(
        sender_address=MINING_SENDER, recipient_address=blockchain_object.node_id, value=MINING_REWARD, signature="")
    # Forge the new Block by adding it to the chain
    previous_hash = blockchain_object.hash(last_block)
    block = blockchain_object.create_block(nonce, previous_hash)
    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    """request.response object"""
    return jsonify(response), 200


# Flask APIs to manage blockchain nodes.
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400
    for node in nodes:
        blockchain_object.add_node(node)
    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain_object.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """POR IMPLEMENTAR"""
    """REGLA PARA FORK"""
    replaced = blockchain_object.resolve_conflicts()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain_object.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain_object.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain_object.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


"""
This is an API that generates wallets(Private/Public key pairs)
"""
@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    """¿AQUÍ DEBO ASEGURARME DE QUE EL ADDRESS SEA UNICO Y DE GUARDAR LOS DATOS DEL WALLET DEL USUARIO EN UNA BASE DE DATOS?
    EL DISTRIBUTED LEDGER ES SOLO DE LAS TRANSACCIONES, NO DE LOS DATOS BANCARIOS DE LOS USUARIOS?"""
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }
    return jsonify(response), 200


"""jsonify() returns a flask.Response() object that already has the approriate content-type header
'application/json' for use with json responses. The json.dumps() method will just return an encoded
string, which would require manually adding the MIME type header."""


"""
API that takes as input sender_address, sender_private_key, recipient_address and value.
Returns the transaction without the private key and the signature.
"""
"""request.form is used to collect values in a form with mehtod=post"""


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    value = request.form['amount']

    transaction = blockchain_mitsein.TransactionObject(
        address_sender, sender_private_key, address_receptor, value)

    response = {'transaction': transaction.to_dict(
    ), 'signature': transaction.sign_transaction()}

    return jsonify(response), 200


"""
You can start a blockchain node from the terminal by going to the blockchain_client folder, and type python 
blockchain_client.py or python blockchain_client.py -p <PORT NUMBER>.
"""

"""--------------------------------------------------------------------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""
"""-------------------------------------------------------USER---------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""



"""--------------------------------------------------------------------------------------------------------------------------------"""
"""-------------------------------------------------------DINERO-------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""
class PaymentForm(FlaskForm):
    address_sender = StringField('Your wallet address:', validators=[InputRequired()])
    address_receptor = StringField('Destination wallet address', validators=[InputRequired()])
    amount = IntegerField('Amount (MTS)')
    private_key = StringField('Your private key:', validators=[InputRequired()])

@app.route('/payment/new', methods=['POST'])
def new_payment():
    amount = request.json["amount"]
    address_recipient = request.json["address_recipient"]
    address_sender = request.json["address_sender"]
    sender_private_key = request.json["private_key"]
    user_sender = Users.query.filter_by(email=form.address_sender).first()
    user_recipient = Users.query.filter_by(email=form.address_recipient).first()
    if user_sender:
        if user_recipient:
            signature = generate_transaction(address_sender, sender_private_key, address_recipient, amount )[0]["signature"]
            transaction_result = blockchain_object.submit_transaction(address_sender, address_recipient, amount, signature)
            if transaction_result == False:
                response = {'message': 'Invalid Transaction. Transaction could not be added to block!'}
                """jsonify turns the JSON output into a Response object with the application/json mimetype."""
                return jsonify(response), 406
            else:
                response = {'message': 'Transaction will be added to Block ' + str(transaction_result)}
                return jsonify(response), 201
        else:
            response = {'message': 'Invalid recipient address!'}
            """jsonify turns the JSON output into a Response object with the application/json mimetype."""
            return jsonify(response), 406
    else:
        response = {'message': 'Invalid sender address!'}
        """jsonify turns the JSON output into a Response object with the application/json mimetype."""
        return jsonify(response), 406
"""--------------------------------------------------------------------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""

"""--------------------------------------------------------------------------------------------------------------------------------"""
"""---------------------------------------------------------FINANCIERO STOCK EXCHANGE----------------------------------------------"""
"""--------------------------------------------------------------------------------------------------------------------------------"""

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
                    num_transactions, transactions_list, undone_orders_dict = check_num_transactions(
                        order_price, current_orders_dict[order_price])
                    if lead_amount < num_transactions:
                        print("si")
                        lead_amount = num_transactions
                        lead_price = order_price
                        lead_transactions_list = transactions_list
                        lead_undone_orders_dict = undone_orders_dict
                if lead_transactions_list != None:
                    print("Nueva valoración token: \n price:{} \n transactions list: {} \n undone orders dict:{})".format(
                        lead_price, lead_transactions_list, lead_undone_orders_dict))
                    current_orders_dict[str(lead_price)
                                        ] = lead_undone_orders_dict
                    write_orders_dict("Mitsein", current_orders_dict)
                    excecute_transactions(lead_price, lead_transactions_list)
                    write_token_price("Mitsein", lead_price)
                    print("NUEVO DICCIONARIO DE ORDENES:{}".format(
                        get_orders_dict("Mitsein")))
                    lead_amount = 0
                    lead_transactions_list = None
                    lead_undone_orders_dict = None
                    continue
    thread = threading.Thread(target=order_excecutioner)
    thread.start()


"""Dashboard only accesible if logged in"""


@app.route('/stockexchange')
@login_required
def stockexchange():
    orders_dict = get_orders_dict("Mitsein")
    current_price = get_token_details("Mitsein")[2]
    valuation = get_token_details("Mitsein")[3]
    variation = "+50%"
    return render_template('stockexchange.html', name=current_user.email, current_user=current_user, orders_dict=orders_dict, token_price=current_price, valuation=valuation, variation=variation)


@app.route('/mitsein_token_page')
def mitsein_token_page():
    return render_template('mitsein_token_page.html', current_user=current_user)


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
        address, abi, current_price, market_cap = get_token_details("Mitsein")
        prices = Price_history_mitsein.query.all()
        for price in prices:
            print(price)
            json_data = json.dumps({'time': datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S').split(" ")[1], 'value': current_price})
            yield f"data:{json_data}\n\n"
        while True:
            json_data = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S').split(" ")[1], 'value': current_price})
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
    """AQUÍ CAMBIAR METODOLOGIA PARA ENCONTRAR LA CANTIDAD DE FONDOS. ¿DESDE DB? ¿GUARDAR EN OBEJTO DE BLOCKCHAIN?"""
    #if web3.eth.getBalance(address_buyer) >= amount_wei:
    if price_limit != current_price:
        amount_token = amount_eth/price_limit
        if str(price_limit) not in orders_dict.keys():
            orders_dict[str(price_limit)] = {
                "buy": [{'address': address_buyer, 'amount': amount_token}], "sell": []}
        else:
            if orders_dict[str(price_limit)] != None:
                orders_dict[str(price_limit)]["buy"].append(
                    {'address': address_buyer, 'amount': amount_token})
            else:
                orders_dict[str(price_limit)] = {
                    "buy": [{'address': address_buyer, 'amount': amount_token}], "sell": []}
    else:
        amount_token = amount_eth/current_price
        if str(current_price) not in orders_dict.keys():
            orders_dict[str(current_price)] = {
                "buy": [{'address': address_buyer, 'amount': amount_token}], "sell": []}
        else:
            if orders_dict[str(current_price)] != None:
                orders_dict[str(current_price)]["buy"].append(
                    {'address': address_buyer, 'amount': amount_token})
            else:
                orders_dict[str(current_price)] = {
                    "buy": [{'address': address_buyer, 'amount': amount_token}], "sell": []}
    write_orders_dict("Mitsein", orders_dict)
    orders_dict = get_orders_dict("Mitsein")
    print("Orden de Compra realizada. Nuevo diccionario de ordenes:{}".format(
        orders_dict))

    return redirect(url_for('stockexchange'))


@app.route('/sell-stock-mitsein', methods=['POST'])
def sell_stock():
    current_price = get_token_details("Mitsein")[2]
    amount_eth = int(request.form.get('amount_eth', 0))
    amount_wei = amount_eth*10**18
    price_limit = int(request.form.get('price', 0))
    address_seller = request.form.get('address', 0)
    orders_dict = get_orders_dict("Mitsein")
    """AQUÍ CAMBIAR METODOLOGIA PARA ENCONTRAR LA CANTIDAD DE FONDOS. ¿DESDE DB? ¿GUARDAR EN OBEJTO DE BLOCKCHAIN?"""
    #if web3.eth.getBalance(address_seller) >= amount_wei:
    if price_limit != current_price:
        amount_token = amount_eth/price_limit
        if str(price_limit) not in orders_dict.keys():
            orders_dict[str(price_limit)] = {
                "sell": [{'address': address_seller, 'amount': amount_token}], "buy": []}
        else:
            if "sell" in orders_dict[str(price_limit)].keys():
                orders_dict[str(price_limit)]["sell"].append(
                    {'address': address_seller, 'amount': amount_token})
            else:
                orders_dict[str(price_limit)]["sell"] = [
                    {'address': address_seller, 'amount': amount_token}]
    else:
        amount_token = amount_eth/current_price
        if str(current_price) not in orders_dict.keys():
            orders_dict[str(current_price)] = {
                "sell": [{'address': address_seller, 'amount': amount_token}], "buy": []}
        else:
            if "sell" in orders_dict[str(current_price)].keys():
                orders_dict[str(current_price)]["sell"].append(
                    {'address': address_seller, 'amount': amount_token})
            else:
                orders_dict[str(current_price)]["sell"] = [
                    {'address': address_seller, 'amount': amount_token}]
    write_orders_dict("Mitsein", orders_dict)
    orders_dict = get_orders_dict("Mitsein")
    print("Orden de Venta realizada. Nuevo diccionario de ordenes:{}".format(
        orders_dict))
    return redirect(url_for('stockexchange'))


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
    """Checks the number of transactions at a specific price and at an specific time.
    Method that receives current_orders = {"buy":[{"address", "amount"}], "sell":[{"address", "amount"}]} 
    and the price to return the number of transactions possible, the list of transactions and the list of
    transactions not done"""
    if current_orders != None:
        if "sell" in current_orders.keys():
            sell_orders = current_orders["sell"]
            if len(sell_orders) > 0:
                current_seller = sell_orders[0]
            else:
                current_seller = None
        else:
            sell_orders = []
            if len(sell_orders) > 0:
                current_seller = sell_orders[0]
            else:
                current_seller = None
        if "buy" in current_orders.keys():
            buy_orders = current_orders["buy"]
            if len(buy_orders) > 0:
                current_buyer = buy_orders[0]
            else:
                current_buyer = None
        else:
            buy_orders = []
            if len(buy_orders) > 0:
                current_buyer = buy_orders[0]
            else:
                current_buyer = None
        transactions_done = []
        num_transactions = 0
        order_not_done = {"type": None, "address": None, "amount": None}
        while len(sell_orders) > 0 and len(buy_orders) > 0:
            if current_seller != None and current_buyer != None:
                if current_seller["amount"] > current_buyer["amount"]:
                    amount_diference = current_seller["amount"] - \
                        current_buyer["amount"]
                    transactions_done.append(
                        {"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_buyer["amount"]})
                    current_seller["amount"] = amount_diference
                    """He aquí una linea muy importtante: La siguiente linea implica que el precio es determinado mediante el descubrimiento del precio con mayor numero 
            de tokens transados en un momento(FIJO O VARIABLE?) dado"""
                    num_transactions += current_buyer["amount"]
                    order_not_done = {
                        "type": "Sell", "address": current_seller["address"], "amount": amount_diference}
                    if len(buy_orders) > 0:
                        buy_orders.pop(0)
                    if len(buy_orders) > 0:
                        current_buyer = buyers_list[0]
                elif current_seller["amount"] == current_buyer["amount"]:
                    transactions_done.append(
                        {"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_seller["amount"]})
                    num_transactions += current_seller["amount"]
                    order_not_done = current_seller
                    order_not_done = {"type": None,
                                      "address": None, "amount": None}
                    if len(buy_orders) > 0:
                        buy_orders.pop(0)
                    if len(sell_orders) > 0:
                        sell_orders.pop(0)
                    if len(buy_orders) > 0:
                        current_buyer = buy_orders[0]
                    if len(sell_orders) > 0:
                        current_seller = sell_orders[0]
                else:
                    amount_diference = current_buyer["amount"] - \
                        current_seller["amount"]
                    transactions_done.append(
                        {"address_buyer": current_buyer["address"], "address_seller": current_seller["address"], "amount": current_seller["amount"]})
                    current_buyer["amount"] = amount_diference
                    num_transactions += current_seller["amount"]
                    order_not_done = {
                        "type": "Buy", "address": current_buyer["address"], "amount": amount_diference}
                    if len(sell_orders) > 0:
                        sell_orders.pop(0)
                    if len(sell_orders) > 0:
                        current_seller = sell_orders[0]
        undone_orders_dict = {"buy": [], "sell": []}
        if order_not_done["type"] != None:
            if order_not_done["type"] == "Buy":
                buy_orders.insert(
                    0, {"address": order_not_done["address"], "amount": order_not_done["amount"]})
            else:
                sell_orders.insert(
                    0, {"address": order_not_done["address"], "amount": order_not_done["amount"]})
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
    """
    contract = web3.eth.contract(
        address=address,
        abi=abi)
    """
    Users.query.all()
    Users.query.filter_by(address='admin').first()
    for transaction_dict in transactions_list:
        address_buyer = transaction_dict["address_buyer"]
        address_seller = transaction_dict["address_seller"]
        amount = transaction_dict["amount"]
        """obtener private key en el form!!!"""
        amount_mts = int(amount*int(price_limit))
        try:
            """Las siguientes lineas señalan el medio de validación de transacciones"""
            """
            A través de Ethereum:
            contract.functions.buyTokens(address_buyer).transact(
                {'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
            contract.functions.buyTokens(address_buyer).transact(
                {'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
            """
            transaction = blockchain_mitsein.TransactionObject(address_buyer, sender_private_key, address_seller, amount_mts)
            response = {'transaction': transaction.to_dict(
            ), 'signature': transaction.sign_transaction()}
            transaction_result = blockchain_object.submit_transaction(address_buyer, address_seller, amount_mts, response['signature'])
            """FALTA COMPLETAR!!!"""
            if transaction_result == False:
                pass
            else:
                pass
        except:
            print("There has been a problem with the transaction")
            continue
        """Escritura a Base de Datos"""
        new_order = Orders_history_mitsein(buyer_id=address_buyer, seller_id=address_seller,
                                           amount=amount, price=price_limit, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        db.session.add(new_order)
        db.session.commit()
    new_price = Price_history_mitsein(
        price=price_limit, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    db.session.add(new_price)
    db.session.commit()


if __name__ == "__main__":
    db.create_all()
    start_backgrounds()
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(debug=True, threaded=True)

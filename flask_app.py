import json
import random
import time
import sys
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
with open('tokens.json', "r") as json_file:
    tokens = json.load(json_file)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    sirname = db.Column(db.String(50))
    age = db.Column(db.Integer)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

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
    return render_template('ecoexchange.html', name=current_user.email)


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
    token_eth_balance = (web3.eth.getBalance(address))/1000000000000000000
    def generate_data():
        while True:
            json_data = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': token_eth_balance})
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
    amount_eth = int(request.form.get('number', 0))
    amount_wei = amount_eth*10**18
    address_buyer = request.form.get('address', 0)
    if web3.eth.getBalance(address_buyer) >= amount_wei:
        contract.functions.buyTokens(address_buyer).transact({ 'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
    return redirect(url_for('ecoexchange'))


@app.route('/sell-stock-mitsein', methods=['POST'])
def sell_stock():
    token_details_dict = tokens["Mitsein"]
    address = token_details_dict["address"]
    abi = token_details_dict["abi"]
    contract = web3.eth.contract(
    address=address,
    abi=abi)
    amount_eth = int(request.form.get('number', 0))
    amount_wei = amount_eth*10**18
    address_buyer = request.form.get('address', 0)
    if web3.eth.getBalance(address_buyer) >= amount_wei:
        contract.functions.buyTokens(address_buyer).transact({ 'from': address_buyer, 'gas': 4712388, 'value': amount_wei})
    return redirect(url_for('ecoexchange'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, threaded=True)              
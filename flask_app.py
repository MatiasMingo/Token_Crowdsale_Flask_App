from flask import Flask, request, render_template, redirect, url_for, Response, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import token_interaction
import json, datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secretkeyyy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
                return redirect(url_for('dashboard'))
        
        return '<h2>Invalid email or password</h2>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(email=form.email.data, password=hashed_password, name=form.name, sirname=form.sirname)
        db.session.add(new_user)
        db.session.commit()
        #return '<h1>' + form.email.data + ' ' + form.password.data +'</h1>'

    return render_template('signup.html', form=form)

"""Dashboard only accesible if logged in"""
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.email)

@app.route('/payments')
@login_required
def payments():
    return render_template('payments.html', name=current_user.email)

@app.route('/stock_exchange')
@login_required
def stock_exchange():
    return render_template('stock_exchange.html', name=current_user.email)

@app.route('/economical_organization')
@login_required
def economical_organization():
    return render_template('economical_organization.html', name=current_user.email)
"""
@app.route('/chart-data')
def chart_data():
    def obtain_data_token():
        while True:
            data_json = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': })  
            yield f"data:{json_data}\n\n"
            time.sleep(1)
    return Response(obtain_data_token(), mimetype=)
"""

@app.route('/buy-stock', methods=['POST'])
def buy_stock(abi, address):
    abi = json.loads('[{"constant": false, "inputs": [{"name": "account", "type": "address"} ], "name": "addWhitelisted", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function"}, {"constant": false, "inputs": [{"name": "account", "type": "address"} ], "name": "removeWhitelisted", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function"}, {"constant": true, "inputs": [], "name": "rate", "outputs": [{"name": "", "type": "uint256"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [{"name": "account", "type": "address"} ], "name": "isWhitelisted", "outputs": [{"name": "", "type": "bool"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [], "name": "weiRaised", "outputs": [{"name": "", "type": "uint256"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": false, "inputs": [], "name": "renounceWhitelistAdmin", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function"}, {"constant": true, "inputs": [], "name": "wallet", "outputs": [{"name": "", "type": "address"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": false, "inputs": [{"name": "account", "type": "address"} ], "name": "addWhitelistAdmin", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function"}, {"constant": true, "inputs": [{"name": "account", "type": "address"} ], "name": "isWhitelistAdmin", "outputs": [{"name": "", "type": "bool"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [], "name": "remainingTokens", "outputs": [{"name": "", "type": "uint256"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [], "name": "tokenWallet", "outputs": [{"name": "", "type": "address"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": false, "inputs": [], "name": "renounceWhitelisted", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function"}, {"constant": false, "inputs": [{"name": "beneficiary", "type": "address"} ], "name": "buyTokens", "outputs": [], "payable": true, "stateMutability": "payable", "type": "function"}, {"constant": true, "inputs": [], "name": "token", "outputs": [{"name": "", "type": "address"} ], "payable": false, "stateMutability": "view", "type": "function"}, {"inputs": [{"name": "_rate", "type": "uint256"}, {"name": "_wallet", "type": "address"}, {"name": "_token", "type": "address"}, {"name": "_tokenWallet", "type": "address"} ], "payable": false, "stateMutability": "nonpayable", "type": "constructor"}, {"payable": true, "stateMutability": "payable", "type": "fallback"}, {"anonymous": false, "inputs": [{"indexed": true, "name": "purchaser", "type": "address"}, {"indexed": true, "name": "beneficiary", "type": "address"}, {"indexed": false, "name": "value", "type": "uint256"}, {"indexed": false, "name": "amount", "type": "uint256"} ], "name": "TokensPurchased", "type": "event"}, {"anonymous": false, "inputs": [{"indexed": true, "name": "account", "type": "address"} ], "name": "WhitelistedAdded", "type": "event"}, {"anonymous": false, "inputs": [{"indexed": true, "name": "account", "type": "address"} ], "name": "WhitelistedRemoved", "type": "event"}, {"anonymous": false, "inputs": [{"indexed": true, "name": "account", "type": "address"} ], "name": "WhitelistAdminAdded", "type": "event"}, {"anonymous": false, "inputs": [{"indexed": true, "name": "account", "type": "address"} ], "name": "WhitelistAdminRemoved", "type": "event"} ]')
    address = "0x8d394914a414F9237115E58E2800b674B80A64D6"
    contract = web3.eth.contract(
    address=address,
    abi=abi)
    amount_eth = float(request.form.get('number', 0))
    amount_wei = amount_eth*10**18
    address_buyer = request.form.get('address', 0)
    token_amount = contract.functions.getTokenAmount(amount_wei)
    if token_amount <= contract.functions.remainingTokens():
        contract.functions.buyTokens(address_buyer, {value : amount_wei , sender : address_buyer});


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True, threaded=True)              
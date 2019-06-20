from flask import Flask, request, render_template
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secretkeyyy'
Bootstrap(app)

class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

@app.route("/")
def index():
    return render_template("homepage.html", name="homepage")

@app.route('/login')
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/user/<username>')
def profile(username):
    return '{}\'s profile'.format(username)


if __name__ == "__main__":
	app.run(debug=True)
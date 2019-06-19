from flask import Flask, request, render_template
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("homepage.html", name="homepage")

@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        if valid_login(request.form['username'],
                       request.form['password']):
            return log_the_user_in(request.form['username'])
        else:
            error = 'Invalid username/password'
    # the code below is executed if the request method
    # was GET or the credentials were invalid
    return render_template('login.html', error=error)

@app.route('/user/<username>')
def profile(username):
    return '{}\'s profile'.format(username)


if __name__ == "__main__":
	app.run(debug=True)
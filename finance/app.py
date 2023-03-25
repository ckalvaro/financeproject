import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    current_cash = db.execute("SELECT cash FROM users WHERE id = (?)", user_id)[0]["cash"]
    stocks = db.execute("SELECT symbol, name, SUM(shares) AS qty, price FROM transactions WHERE user_id = (?) GROUP BY symbol ORDER BY (price * shares) DESC", user_id)
    total_value = current_cash
    for stock in stocks:
        total_value += stock["price"] * stock["qty"]
    return render_template("index.html", stocks=stocks, current_cash = current_cash, total_value = total_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    user_id = session["user_id"]
    if request.method == "POST":
        #we convert to upper so we can see the symbol in uppercase later
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)
        #error handling
        if not symbol:
            return apology("Must provide a symbol")
        elif not stock:
            return apology("Couldn't find symbol")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares must be a integer")

        if shares <= 0:
            return apology("Shares must be greater than 0")
        #we use the user_id to check how much cash he has left
        current_cash = db.execute("SELECT cash FROM users WHERE id = (?)", user_id)[0]["cash"]
        #set up the info for the stock we are about to buy
        stock_name = stock["name"]
        stock_price = stock["price"]
        total_cost = stock_price * shares
        #let's make sure the user has enough cash to buy the amount of stocks required

        if current_cash < total_cost:
            return apology("Not enough cash")
        #the purchase was succesfull, let's register it in the db
        else:
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", current_cash - total_cost, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, symbol, action) VALUES (?, ?, ?, ?, ?, ?)", user_id, stock_name, shares, stock_price, symbol, 'buy')
        return redirect('/')
    #if method = get
    elif request.method == "GET":
        symbol_to_buy= request.args.get("buys", default=None)
        #we check if the user is trying to buy a stock from the index page, and if so we load up the buy form with the info from the stock it's trying to buy
        if symbol_to_buy:
            return render_template("buy.html", symbol_to_buy=symbol_to_buy)
        else:
            symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol", user_id)
            return render_template("buy.html", symbols=symbols)



@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = (?) ORDER BY time DESC", user_id)
    return render_template("history.html", transactions = transactions)

@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def addcash():
    user_id = session["user_id"]
    if request.method == "GET":
        return render_template("add_cash.html")
    elif request.method == "POST":
        cash_to_add = int(request.form.get("add_cash"))
        if not cash_to_add:
            return apology("Please enter a valid amount")
        else:
            current_cash = db.execute("SELECT cash FROM users WHERE id = (?)", user_id)[0]["cash"]
            updated_cash = current_cash + cash_to_add
            #update the amount of cash with the additional
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", updated_cash, user_id)
            return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")

    elif request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol or symbol is None:
            return apology("You need to input a symbol")

        stock = lookup(symbol)
        if not stock or stock is None:
            return apology("Couldn't find the symbol")
        stock_price = stock["price"]
        return render_template("quoted.html", stock=stock, stock_price = stock_price)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        if not username:
            return apology("You need to enter a username")
        elif not password:
            return apology("You must enter a password")
        elif not confirmation:
            return apology("Please re-enter your password to confirm it")
        elif password != confirmation:
            return apology("The passwords don't match")
        else:
            hashed_pw = generate_password_hash(password)
            try:
                db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_pw)
                return redirect("/")
            except:
                return apology("Username already in use")





@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        stock_price = float(lookup(symbol)["price"])
        stock_name = lookup(symbol)["name"]

        if not symbol:
            return apology("Couldn't find the symbol you are trying to sell")
        elif not shares or shares <= 0:
            return apology("Shares must be a positive integer")
        #we are going to check if user owns the symbol
        user_owned = db.execute("SELECT SUM(shares) as sumshares FROM transactions WHERE user_id = (?) AND symbol = (?) GROUP BY symbol", user_id, symbol)[0]["sumshares"]
        if not user_owned:
            return apology("You do not own any shares of that stock")
        elif user_owned < shares:
            return apology("You do not own that many shares")
        else:
            current_cash = db.execute("SELECT cash FROM users WHERE id = (?)", user_id)[0]["cash"]
            value_to_sell = stock_price * shares
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", current_cash + value_to_sell, user_id )
            db.execute("INSERT INTO transactions (user_id, name, shares, price, symbol, action) VALUES (?, ?, ?, ?, ?, ?)", user_id, stock_name, -shares, stock_price, symbol, 'sell')
        return redirect('/')

    elif request.method == "GET":
        symbol_to_sell= request.args.get("sells", default=None)
        if symbol_to_sell:
            return render_template("sell.html", symbol_to_sell=symbol_to_sell)
        else:
            symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol", user_id)
            return render_template("sell.html", symbols=symbols)


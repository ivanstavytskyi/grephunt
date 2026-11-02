import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    connection = sqlite3.connect("db.sqlite")
    return str(connection.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall())

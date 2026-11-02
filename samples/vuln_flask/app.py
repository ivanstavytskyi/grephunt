# Intentionally vulnerable application. Scanner fixture only.
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "super-secret-hardcoded-key"


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    return str(conn.execute("SELECT * FROM users WHERE id = '" + uid + "'").fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

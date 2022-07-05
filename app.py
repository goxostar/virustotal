import os
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

FREE_DAILY_LIMIT = 500
FREE_RATE = 4
FREE_RATE_MINUTE = 60

@app.route("/", methods=["GET", "POST"])
def home():    
    return render_template("home.html", FREE_DAILY_LIMIT=FREE_DAILY_LIMIT)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
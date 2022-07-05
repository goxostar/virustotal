import os
from flask import Flask, render_template, request, redirect, url_for


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    return "<p>Hello, World!</p>"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
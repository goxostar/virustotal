import os
import requests
import time
import threading, multiprocessing
from flask import Flask, flash, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "ggggggggggggggggggggggggggggg"
app.config['MAX_CONTENT_LENGTH'] = 32 * 1000 * 1000

FREE_DAILY_LIMIT = 500
FREE_RATE = 4
FREE_RATE_MINUTE = 60

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/file', methods=['GET', 'POST'])
def file():
    global FREE_DAILY_LIMIT
    
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))       
            return redirect(url_for('filescan', name=filename))
    return render_template("file.html", FREE_DAILY_LIMIT=FREE_DAILY_LIMIT)

@app.route("/filescan", methods=["GET", "POST"])
def filescan():  
    htmlstatus = "Analyzing..."
    points=0
    # Get file name -> ex "testfile.txt"
    fname = request.args.get('name')   
    # File scan request  
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": open("./uploads/{}".format(fname), "rb")}
    headers = {
        "Accept": "application/json",
        "x-apikey": "542883fc18664cc7ae3dab65b8245384b08386329ec29e43ebaa6511526e7673"
    }
    response = requests.post(url, files=files, headers=headers)
    
    # Get file analysis id from response
    analysis_id = response.json()['data']['id']  
    # Analysis Request  
    url = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
    headers = {
        "Accept": "application/json",
        "x-apikey": "542883fc18664cc7ae3dab65b8245384b08386329ec29e43ebaa6511526e7673"
    }
    response = requests.get(url, headers=headers)
    print("Status = ", response.json()['data']['attributes']['status'])
                
    # Get file analysis result  
    if response.json()['data']['attributes']['status'] == "completed":
        points = response.json()['data']['attributes']['stats']['suspicious'] + response.json()['data']['attributes']['stats']['malicious']
        print("Points = ", points) 
        htmlstatus = "Scan complete!"  
        isMalicious = ""
        if points > 0:
            isMalicious = "Malicious"
        else:
            isMalicious = "Not malicious"        
    else:
        points = 0
        htmlstatus = "Scanning..."
        isMalicious = "Not scanned yet."        
    return render_template("filescan.html", points=points, htmlstatus=htmlstatus, isMalicious=isMalicious)

@app.route("/filescancomplete", methods=["GET", "POST"])
def filescancomplete():    
    return render_template("filescancomplete.html", FREE_DAILY_LIMIT=FREE_DAILY_LIMIT)    

@app.route("/", methods=["GET", "POST"])
def home():    
    return render_template("home.html", FREE_DAILY_LIMIT=FREE_DAILY_LIMIT)    

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)


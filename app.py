import os
import requests
from ratelimit import limits, RateLimitException, sleep_and_retry
from flask import Flask, flash, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import hashlib

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "ggggggggggggggggggggggggggggg"
app.config['MAX_CONTENT_LENGTH'] = 32 * 1000 * 1000

# Free API Daily Limit = 500
# Free API Request per minutes is 4
FREE_DAILY_LIMIT = 500
FREE_RATE = 4
FREE_RATE_MINUTE = 60

# Store Hash of Files to prevent redundant upload
already_uploaded = {}

# Get the hash value of a file
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

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
@sleep_and_retry
@limits(calls=FREE_RATE, period=FREE_RATE_MINUTE)
def filescan(): 
    global FREE_DAILY_LIMIT
    if request.args.get('name') is None:
        return redirect(url_for('file'))    
    
    # Get file name -> ex "testfile.txt"
    # Get Hash value of file
    fname = request.args.get('name')  
    filehash = sha256sum("./uploads/{}".format(fname))

    # File Request
    url_file = "https://www.virustotal.com/api/v3/files"
    files = {"file": open("./uploads/{}".format(fname), "rb")}
    headers_file = {
            "Accept": "application/json",
            "x-apikey": "542883fc18664cc7ae3dab65b8245384b08386329ec29e43ebaa6511526e7673"
    }
    
    # File scan request 
    # Check file hash already uploaded 
    if filehash in already_uploaded:
        if FREE_DAILY_LIMIT>0:
            analysis_id = already_uploaded[filehash]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
            headers_analysis = {
            "Accept": "application/json",
            "x-apikey": "542883fc18664cc7ae3dab65b8245384b08386329ec29e43ebaa6511526e7673"
            }
            response = requests.get(url_analysis, headers=headers_analysis)
            FREE_DAILY_LIMIT = FREE_DAILY_LIMIT - 1
            return response.json()
        else:
            return "Daily limit reached"
    else:
        if FREE_DAILY_LIMIT>0:                   
            response = requests.post(url_file, files=files, headers=headers_file)
            FREE_DAILY_LIMIT = FREE_DAILY_LIMIT - 1
            # Get file analysis id from response
            analysis_id = response.json()['data']['id']  
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
            headers_analysis = {
            "Accept": "application/json",
            "x-apikey": "542883fc18664cc7ae3dab65b8245384b08386329ec29e43ebaa6511526e7673"
            }       
            response = requests.get(url_analysis, headers=headers_analysis)
            FREE_DAILY_LIMIT = FREE_DAILY_LIMIT - 1
            already_uploaded[filehash] = analysis_id            
            return response.json()  
        else:
            return "Daily limit Reached"    
    

@app.route("/", methods=["GET", "POST"])
def home():    
    return render_template("home.html", FREE_DAILY_LIMIT=FREE_DAILY_LIMIT)    

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)


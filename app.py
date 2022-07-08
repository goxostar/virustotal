import os
import requests
from ratelimit import limits, sleep_and_retry
from flask import Flask, flash, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from sqlalchemy import false, true
from wtforms import StringField, SubmitField
from wtforms.validators import InputRequired, Length
from werkzeug.utils import secure_filename
import hashlib

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "ggggggggggggggggggggggggggggg"
app.config['MAX_CONTENT_LENGTH'] = 32 * 1000 * 1000

# API KEYS (WILL BE ADDED TO ENV VARIABLES)
FREE_API_KEY = "542883fc18664cc7ae3dab65b8245384b08386329ec29e43ebaa6511526e7673"
PREMIUM_API_KEY = "PREMIUMAPIKEY"

# Free API Daily Limit = 500
# Free API Request per minutes is 4
FREE_DAILY_LIMIT = 500
FREE_RATE = 4
FREE_RATE_MINUTE = 60

# PREMIUM LIMIT
PREMIUM_LIMIT = 100

# VT API GET DAILY LIMIT 
url_free_daily = "https://www.virustotal.com/api/v3/users/{}/overall_quotas".format(FREE_API_KEY)
headers_free_daily = {
    "Accept": "application/json",
    "x-apikey": "{}".format(FREE_API_KEY)
}
response_free_daily = requests.get(url_free_daily, headers=headers_free_daily)
USED_DAILY_LIMIT = response_free_daily.json()['data']['api_requests_daily']['user']['used']

# VT GET PREMIUM API LIMIT
# WIL GET PREMIUM API LIMIT
PREMIUM_USED_LIMIT = 0

# Store Hash of Files to prevent redundant upload
already_uploaded = {}

# Store already scanned urls
already_scanned_url = {}

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

class UrlForm(FlaskForm):
  url = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Url"})

  submit = SubmitField('Lookup')

class SearchForm(FlaskForm):
  search = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Domain & URL & IP"})

  submit = SubmitField('Search')

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
    global USED_DAILY_LIMIT
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
            "x-apikey": "{}".format(FREE_API_KEY)
    }
        
    # File scan request 
    # Check file hash already uploaded 
    if filehash in already_uploaded:               
        if USED_DAILY_LIMIT<500:
            analysis_id = already_uploaded[filehash]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
            headers_analysis = {
            "Accept": "application/json",
            "x-apikey": "{}".format(FREE_API_KEY)
            }
            response = requests.get(url_analysis, headers=headers_analysis)     
            return response.json()
        elif PREMIUM_USED_LIMIT<100:
            analysis_id = already_uploaded[filehash]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
            headers_analysis = {
            "Accept": "application/json",
            "x-apikey": "{}".format(PREMIUM_API_KEY)
            }
            response = requests.get(url_analysis, headers=headers_analysis)     
            return response.json()
        else:
            return "Limit reached"
    else:        
        if USED_DAILY_LIMIT<500:                  
            response = requests.post(url_file, files=files, headers=headers_file)            
            # Get file analysis id from response
            analysis_id = response.json()['data']['id']  
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
            headers_analysis = {
            "Accept": "application/json",
            "x-apikey": "{}".format(FREE_API_KEY)
            }       
            response = requests.get(url_analysis, headers=headers_analysis)
            USED_DAILY_LIMIT = USED_DAILY_LIMIT + 1
            already_uploaded[filehash] = analysis_id            
            return response.json()  
        elif PREMIUM_USED_LIMIT<100:
            response = requests.post(url_file, files=files, headers=headers_file)            
            # Get file analysis id from response
            analysis_id = response.json()['data']['id']  
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
            headers_analysis = {
            "Accept": "application/json",
            "x-apikey": "{}".format(PREMIUM_API_KEY)
            }       
            response = requests.get(url_analysis, headers=headers_analysis)
            PREMIUM_USED_LIMIT = PREMIUM_USED_LIMIT + 1
            already_uploaded[filehash] = analysis_id            
            return response.json() 
        else:
            return "Limit Reached"    

@app.route('/url', methods=['GET','POST'])
def url():

    form = UrlForm()

    if form.validate_on_submit():        
            
        # Login Request with User Input
        url=form.url.data  
        return redirect(url_for('urlscan', url=url))                 

    return render_template('url.html',form=form)

@app.route('/search', methods=['GET','POST'])
def search():

    form = SearchForm()

    if form.validate_on_submit():        
            
        # Search Request with User Input
        search=form.search.data  
        return redirect(url_for('searchscan', search=search))                          

    return render_template('search.html',form=form)

@app.route('/searchscan', methods=['GET','POST'])
@sleep_and_retry
@limits(calls=FREE_RATE, period=FREE_RATE_MINUTE)
def searchscan():
    global USED_DAILY_LIMIT
    if request.args.get('search') is None:
        return redirect(url_for('search'))  
    
    searchname = request.args.get('search')  

    # Search Request
    url_search = "https://www.virustotal.com/api/v3/search?query={}".format(searchname)
    headers_search = {
        "Accept": "application/json",
        "x-apikey": "{}".format(FREE_API_KEY)
    }    

    if USED_DAILY_LIMIT<500:            
            response_search = requests.get(url_search, headers=headers_search) 
            USED_DAILY_LIMIT = USED_DAILY_LIMIT + 1   
            return response_search.json()
    else:
            return "Daily limit reached"   
    
    
@app.route('/urlscan', methods=['GET','POST'])
@sleep_and_retry
@limits(calls=FREE_RATE, period=FREE_RATE_MINUTE)
def urlscan():

    global FREE_DAILY_LIMIT
    global USED_DAILY_LIMIT
    global PREMIUM_USED_LIMIT

    if request.args.get('url') is None:
        return redirect(url_for('url'))
    
    urlname = request.args.get('url')

    # Url Validator
    # Check if url is valid
    prefixes = ["https://", "http://"]
    def validate(url):
        for pre in prefixes:
            url = url.strip(pre)
            if url.startswith("www"):
                return true
            else:
                return false
    
    if validate(urlname) != true:
        return redirect(url_for('url'))                

    # URL Request
    url_scan = "https://www.virustotal.com/api/v3/urls"
    payload = "url={}".format(urlname)
    headers_url = {
    "Accept": "application/json",
    "x-apikey": "{}".format(FREE_API_KEY),
    "Content-Type": "application/x-www-form-urlencoded"
    }

    if urlname in already_scanned_url:
        if USED_DAILY_LIMIT<500:
            analysis_id = already_scanned_url[urlname]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/urls/{}".format(analysis_id)
            headers_analysis = {
                "Accept": "application/json",
                "x-apikey": "{}".format(FREE_API_KEY)
            }
            response = requests.get(url_analysis, headers=headers_analysis)
            USED_DAILY_LIMIT = USED_DAILY_LIMIT + 1
            return response.json()
        elif PREMIUM_USED_LIMIT<100:
            analysis_id = already_scanned_url[urlname]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/urls/{}".format(analysis_id)
            headers_analysis = {
                "Accept": "application/json",
                "x-apikey": "{}".format(PREMIUM_API_KEY)
            }
            response = requests.get(url_analysis, headers=headers_analysis)
            PREMIUM_USED_LIMIT = PREMIUM_USED_LIMIT + 1
            return response.json()
        else:
            return "Limit reached"
    else:
        if USED_DAILY_LIMIT<500:
            response = requests.post(url_scan, data=payload, headers=headers_url)            
            # Get url analysis id from response            
            analysis_id = response.json()['data']['id'].split("-")[1]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/urls/{}".format(analysis_id)
            headers_analysis = {
                "Accept": "application/json",
                "x-apikey": "{}".format(FREE_API_KEY)
            }       
            response = requests.get(url_analysis, headers=headers_analysis)            
            already_scanned_url[urlname] = analysis_id   
            USED_DAILY_LIMIT = USED_DAILY_LIMIT + 2         
            return response.json()  
        elif PREMIUM_USED_LIMIT<100:
            response = requests.post(url_scan, data=payload, headers=headers_url)            
            # Get url analysis id from response            
            analysis_id = response.json()['data']['id'].split("-")[1]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/urls/{}".format(analysis_id)
            headers_analysis = {
                "Accept": "application/json",
                "x-apikey": "{}".format(PREMIUM_API_KEY)
            }       
            response = requests.get(url_analysis, headers=headers_analysis)            
            already_scanned_url[urlname] = analysis_id   
            PREMIUM_USED_LIMIT = PREMIUM_USED_LIMIT + 2         
            return response.json() 
        else:
            return "Limit Reached"


# PREMIUM INTELLEGENCE SEARCH
@app.route('/searchscan_premium', methods=['GET','POST'])
def searchscan_premium():    
    global PREMIUM_USED_LIMIT    
    if request.args.get('search') is None:
        return redirect(url_for('search_premium'))
    search = request.args.get('search') 

    url = "https://www.virustotal.com/api/v3/intelligence/search?query={}&limit=10&descriptors_only=false".format(search)
    headers = {
        "Accept": "application/json",
        "x-apikey": "{}".format(PREMIUM_API_KEY)
    }
    if PREMIUM_USED_LIMIT<100:            
            response = requests.get(url, headers=headers)
            PREMIUM_USED_LIMIT = PREMIUM_USED_LIMIT + 1   
            return response.json()
    else:
            return "Limit reached"    

@app.route("/", methods=["GET", "POST"])
def home():    
    return render_template("home.html", FREE_DAILY_LIMIT=FREE_DAILY_LIMIT, USED_DAILY_LIMIT=USED_DAILY_LIMIT) 

if __name__ == '__main__':    
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
    
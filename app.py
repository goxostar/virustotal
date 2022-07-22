import os
import requests
import redis
import json
import threading
import time
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

redis = redis.Redis(
     host= 'redis',
     port= '6379')
#redis.set('mykey', 'Hello from Python!')
#redis.get('mykey')
#redis.exists('mykey')

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

# Thread for updating used daily limit every 24h
def check_free_daily_Thread():
    global USED_DAILY_LIMIT
    while true:
        response_free_daily = requests.get(url_free_daily, headers=headers_free_daily)
        USED_DAILY_LIMIT = response_free_daily.json()['data']['api_requests_daily']['user']['used']
        # 24h sleep
        print("Free used daily quota updated! It is {}/500! Waiting 24h for next update...".format(USED_DAILY_LIMIT))
        time.sleep(86400)      

# VT GET PREMIUM API LIMIT
# WIL GET PREMIUM API LIMIT
PREMIUM_USED_LIMIT = 0

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
#@sleep_and_retry
#@limits(calls=FREE_RATE, period=FREE_RATE_MINUTE)
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
    if redis.exists(filehash) == 1:               
        if USED_DAILY_LIMIT<500:
            analysis_id = redis.get(filehash).decode('utf-8')            
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/analyses/{}".format(analysis_id)
            headers_analysis = {
            "Accept": "application/json",
            "x-apikey": "{}".format(FREE_API_KEY)
            }
            response = requests.get(url_analysis, headers=headers_analysis)              
            return response.json()
        elif PREMIUM_USED_LIMIT<100:
            analysis_id = redis.get(filehash).decode('utf-8')
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
            response_free_daily = requests.get(url_free_daily, headers=headers_free_daily)
            USED_DAILY_LIMIT = response_free_daily.json()['data']['api_requests_daily']['user']['used']
            redis.set(filehash, analysis_id)                       
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
            redis.set(filehash, analysis_id)                     
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
#@sleep_and_retry
#@limits(calls=FREE_RATE, period=FREE_RATE_MINUTE)
def searchscan():
    global USED_DAILY_LIMIT
    if request.args.get('search') is None:
        return redirect(url_for('search'))  
    
    searchname = request.args.get('search')  

    prefixes = ['http://', 'https://', 'www.']
    if searchname.startswith(tuple(prefixes)):
        searchname = searchname.replace('http://', '')
        searchname = searchname.replace('https://', '')
        searchname = searchname.replace('www.', '')

    # Search Request
    url_search = "https://www.virustotal.com/api/v3/search?query={}".format(searchname)
    headers_search = {
        "Accept": "application/json",
        "x-apikey": "{}".format(FREE_API_KEY)
    }    
    headers_search_premium = {
        "Accept": "application/json",
        "x-apikey": "{}".format(PREMIUM_API_KEY)
    }  

    if redis.exists(searchname) == 1:
        return json.loads(redis.get(searchname))
    else:       
        if USED_DAILY_LIMIT<500:            
            response_search = requests.get(url_search, headers=headers_search)
            response_free_daily = requests.get(url_free_daily, headers=headers_free_daily) 
            USED_DAILY_LIMIT = response_free_daily.json()['data']['api_requests_daily']['user']['used']   
            redis.set(searchname, json.dumps(dict(response_search.json())))                    
            return json.loads(redis.get(searchname))
        elif PREMIUM_USED_LIMIT<100:
            response_search = requests.get(url_search, headers=headers_search_premium) 
            PREMIUM_USED_LIMIT = PREMIUM_USED_LIMIT + 1   
            redis.set(searchname, json.dumps(dict(response_search.json())))                    
            return json.loads(redis.get(searchname))
        else:
            return "Limit reached"   
    
    
@app.route('/urlscan', methods=['GET','POST'])
#@sleep_and_retry
#@limits(calls=FREE_RATE, period=FREE_RATE_MINUTE)
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
    
    #if validate(urlname) != true:
    #   return redirect(url_for('url'))  

    # Making Url a Format, to prevent reduntant requests
    # Ex: http://www.google.com -> www.google.com -> google.com
    # Otherwise http://www.google.com & www.google.com will be scanned twice
    urlname=urlname.replace('http://','')
    urlname=urlname.replace('https://','')    
    urlname=urlname.replace('www.','')            

    # URL Request
    url_scan = "https://www.virustotal.com/api/v3/urls"
    payload = "url={}".format(urlname)
    headers_url = {
    "Accept": "application/json",
    "x-apikey": "{}".format(FREE_API_KEY),
    "Content-Type": "application/x-www-form-urlencoded"
    }
    headers_url_premium = {
    "Accept": "application/json",
    "x-apikey": "{}".format(PREMIUM_API_KEY),
    "Content-Type": "application/x-www-form-urlencoded"
    }    

    if redis.exists(urlname) == 1:
        return json.loads(redis.get(urlname))
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
            response_free_daily = requests.get(url_free_daily, headers=headers_free_daily)      
            USED_DAILY_LIMIT = response_free_daily.json()['data']['api_requests_daily']['user']['used']  
            redis.set(urlname, json.dumps(dict(response.json())))                    
            return json.loads(redis.get(urlname))
        elif PREMIUM_USED_LIMIT<100:
            response = requests.post(url_scan, data=payload, headers=headers_url_premium)            
            # Get url analysis id from response            
            analysis_id = response.json()['data']['id'].split("-")[1]
            # Analysis Request  
            url_analysis = "https://www.virustotal.com/api/v3/urls/{}".format(analysis_id)
            headers_analysis = {
                "Accept": "application/json",
                "x-apikey": "{}".format(PREMIUM_API_KEY)
            }       
            response = requests.get(url_analysis, headers=headers_analysis)        
            PREMIUM_USED_LIMIT = PREMIUM_USED_LIMIT + 2         
            redis.set(urlname, json.dumps(dict(response.json())))                    
            return json.loads(redis.get(urlname)) 
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

    if redis.exists(search) == 1:
        return json.loads(redis.get(search))
    else:
        if PREMIUM_USED_LIMIT<100:            
            response = requests.get(url, headers=headers)
            PREMIUM_USED_LIMIT = PREMIUM_USED_LIMIT + 1   
            redis.set(search, json.dumps(dict(response.json())))                    
            return json.loads(redis.get(search))
        else:
            return "Limit reached"    

@app.route("/", methods=["GET", "POST"])
def home():    
    return render_template("home.html", FREE_DAILY_LIMIT=FREE_DAILY_LIMIT, USED_DAILY_LIMIT=USED_DAILY_LIMIT) 

if __name__ == '__main__':  
    thread_free_daily = threading.Thread(target=check_free_daily_Thread, daemon=True)
    thread_free_daily.start()
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
    
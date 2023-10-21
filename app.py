from flask import Flask, render_template, request, jsonify, redirect, url_for
from pymongo import MongoClient
import csv
import os
from flask_bcrypt import Bcrypt
from datetime import datetime
from bson import json_util
from flask import flash
from datetime import datetime, timedelta
import hashlib
import requests
from flask import session# for login sessions
import logging
from flask import Flask
from datetime import timedelta







app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)





# Session security settings, this keeps info in cookies safe
app.config['SESSION_COOKIE_SECURE'] = False  # For development only
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['WTF_CSRF_ENABLED'] = True
# Set the duration for the session data to be stored
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Sessions last for 1 day

bcrypt = Bcrypt(app)#this is for encrypting login information with mongo

# This global variable stores the timestamp of the last failed attempt and the number of failed attempts in the create user route.
cooldown_info = {"last_attempt": None, "failed_attempts": 0}



#this is to get the database search working with serializable
from flask import Flask, jsonify
from bson import ObjectId
import json  # Import the standard library's json

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return super().default(o)

app.json_encoder = JSONEncoder


# Setup MongoDB connection, this must obviously be running already on localhost for this implementation, but I can change later
client = MongoClient("mongodb://localhost:27017/")



db = client["incident_db"]#database name
users_collection = db["users"]#for login info users
# Check if admin exists in users collection
admin_exists = users_collection.find_one({"username": "admin"})
#if not, create one first time
if not admin_exists:
    hashed_password = bcrypt.generate_password_hash("admin").decode('utf-8')
    users_collection.insert_one({"username": "admin", "password": hashed_password, "type": "superuser"})
    

collection = db["incidents"]#collection name

data_list = []# for posting data to the bottom when submit button pressed

API_KEY_URL = "key"  #This is the API key for URL scan

# helps prevent XSS attacks ---***experimental this changes input***---
def sanitize_input(text):
    # Remove potentially harmful characters or sequences
    return text.replace("<", "").replace(">", "").replace("&", "")

# EDITED Oct. 18th
#for login sessions
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = users_collection.find_one({"username": username})
        
        if user and bcrypt.check_password_hash(user["password"], password):
            session.permanent = True  # The session will last beyond a single browser session
            session["username"] = username
            session["user_type"] = user["type"]
            print('Session data at /login:', session.items())
            return redirect(url_for("dashboard"))
        else:
            # Handle incorrect login credentials
            flash("Invalid credentials")
            return "Invalid credentials", 401
            
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    save_data = request.form.get("save_data")  # This will come from the prompt
    if save_data == "yes" and data_list:
        collection.insert_many(data_list)
        data_list.clear()

    session.clear()  # Clear the session to log the user out
    return redirect(url_for("login"))



@app.route("/create-user", methods=["GET", "POST"])
def create_user():
    # if session.get("user_type") != "superuser":
        # return "Access denied", 403

    # This is for the wait time if a user tries to enter the wrong passkey too many times.
    global cooldown_info
    current_time = datetime.now()

        # Check if the user is in cooldown period
    if cooldown_info["last_attempt"] and (current_time - cooldown_info["last_attempt"]) < timedelta(minutes=10):
        flash("Too many incorrect attempts. Please try again later.")
        return redirect(url_for("homepage"))


    if request.method == "POST":
        username = request.form.get("username")
        password = bcrypt.generate_password_hash(request.form.get("password")).decode('utf-8')
        user_type = request.form.get("user_type")
        
        #Chris added the passkey verification here
        entered_passkey = request.form.get("passkey")
        # salt to add to encrypted key
        salt = "ravisethi"
        correct_passkey_hash = hashlib.sha256(("team7csc436!!!" + salt).encode()).hexdigest()
        
        entered_passkey_hash = hashlib.sha256((entered_passkey + salt).encode()).hexdigest()

        if entered_passkey_hash != correct_passkey_hash:
            cooldown_info["failed_attempts"] += 1
            if cooldown_info["failed_attempts"] >= 10:
                cooldown_info["last_attempt"] = current_time
                flash("Too many incorrect attempts. Please try again later.")
                return redirect(url_for("homepage"))
            else:
                flash("Incorrect passkey. Please try again.")
                return redirect(url_for("create_user"))

        # Reset failed attempts on successful passkey entry
        cooldown_info["failed_attempts"] = 0
        #end new passkeycode

        users_collection.insert_one({"username": username, "password": password, "type": user_type})#type is superuser or normal. This affects visibility 
        print("User Created")
        return render_template("login.html"), 200

    print("Unable to create user")
    return render_template("create_user.html")

# --------------------------- ADDED Oct. 18th ---------------------------
# added to display homepage
@app.route("/homepage", methods=["GET"])
def homepage():
    return render_template("homepage.html")


# added to link to view incidents page
@app.route("/view-incidents", methods=["GET"])
def view_incidents():
    return render_template("viewIncidents.html")


# added to link to view statistics page
@app.route("/view-stats", methods=["GET"])
def view_stats():
    return render_template("stats.html")


# added to display homepage
@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")

# ------------------------------------------------------------------------

# EDITED Oct. 18th
#for loading index, it displays any data in data list at the bottom when loaded
@app.route("/")

def start():
    return render_template("homepage.html")

# EDITED Oct. 18th
@app.route("/index")
def index():
    logging.debug('Session data: %s', session.items())
    print('Session data at /index:', session.items())  # Print directly to the console
    
    if "username" not in session:#check login info
        return redirect(url_for("login"))
    return render_template("createIncident.html", data_list=data_list)


#submit button that will post (display at bottom) the incident data that was entered in all the text boxes
@app.route("/submit", methods=["POST"])
def submit_data():
    if "username" not in session:
        return redirect(url_for("login"))#call this python function to get the text box data
    
    # Validate the date
    date_str = request.form["date"]
    try:
        valid_date = datetime.strptime(date_str, '%m-%d-%Y')  # assuming format is MM-DD-YYYY
    except ValueError:
        return "Invalid date format. Expected MM-DD-YYYY.", 400
    
    #sanitize
    incident_number = sanitize_input(request.form["incident_number"])
    analyst_name = sanitize_input(request.form["analyst_name"])

    data = {
        "incident_number": incident_number,
	    "severity": request.form["severity"],  # Adding severity
        "date": request.form["date"],
        "analyst_name": analyst_name,
        "incident_type": request.form["incident_type"],
        "email_address": request.form["email_address"],
        "subject_line": request.form["subject_line"],
        "notes": request.form["notes"],
        "emails_sent": request.form["emails_sent"],
        "replies": request.form["replies"]
    }
    data_list.append(data)
    return redirect(url_for('index'))#basically reload the page on client so they see updated submitted data


#store data that's display on the bottom of the page in mongo database
@app.route("/export-to-mongo", methods=["GET"])
def export_to_mongo():
    if "username" not in session:
        return redirect(url_for("login"))

    if data_list:
        collection.insert_many(data_list)
        #data_list.clear() maybe clear the screen - dunno if I want to do this
    return redirect(url_for('index'))#reload the screen for client


#load data 
@app.route("/load-from-mongo", methods=["GET"])
def load_from_mongo():
    if "username" not in session:
        return redirect(url_for("login"))

    global data_list  
    data_list = list(collection.find({}, {'_id': 0}))#at the moment, this will get all the data in the collection and load it
    return redirect(url_for('index'))


#When this button is pressed, get all the keys in a list structure and write to csv, then append data in each column
@app.route("/export-to-csv", methods=["GET"])
def export_to_csv():
    if "username" not in session:
        return redirect(url_for("login"))

    keys = ["incident_number","severity", "date", "analyst_name", "incident_type", "email_address", "subject_line", "notes", "emails_sent", "replies"]
    mode = 'a' if os.path.exists("data.csv") else 'w'#if file is there append data, otherwise create a new file
    with open("data.csv", mode, newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)#create a dictionary writer to output to csv
        if mode == 'w':  
            dict_writer.writeheader()
        dict_writer.writerows(data_list)
    return "Data exported to CSV!", 200#I need error checking


#this just clears the bottom of the screen data and reloads
@app.route("/clear-data", methods=["GET"])
def clear_data():
    if "username" not in session:
        return redirect(url_for("login"))

    data_list.clear()
    return redirect(url_for('index'))
'''
apis for external malware tools below

'''


#urlscan api - description is on their website - API KEY ISN'T READY YET. THIS WON'T WORK IF THERE IS NO API KEY
@app.route("/urlscan", methods=["GET"])
def urlscan():
    if "username" not in session:
        return redirect(url_for("login"))

    url = request.args.get('url')
    
    headers = {
        "Content-Type": "application/json",#get json data
        "API-Key": API_KEY_URL
    }
    
    data = {
        "url": url, # this is the url I want to check
        "visibility": "public"
    }
    #api call
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    
    if response.status_code == 200:
        return jsonify(response.json())#display json data
    else:
        return jsonify({"error": f"Error scanning URL! Response: {response.text}"}), 400



@app.route("/search-database", methods=["POST"])
def search_database():
    query = request.form.get("query")

    # Search all fields for the query
    results = collection.find({
        "$or": [
            {"incident_number": {"$regex": query, "$options": "i"}},
            {"severity": {"$regex": query, "$options": "i"}},
            {"date": {"$regex": query, "$options": "i"}},
            {"analyst_name": {"$regex": query, "$options": "i"}},
            {"incident_type": {"$regex": query, "$options": "i"}},
            {"email_address": {"$regex": query, "$options": "i"}},
            {"subject_line": {"$regex": query, "$options": "i"}},
            {"notes": {"$regex": query, "$options": "i"}},
            {"emails_sent": {"$regex": query, "$options": "i"}},
            {"replies": {"$regex": query, "$options": "i"}}
        ]
    })
      
    # Convert each MongoDB document to a dictionary that's JSON serializable
    serialized_results = []
    for result in results:
        # Convert ObjectId to string
        if '_id' in result:
            result['_id'] = str(result['_id'])
        serialized_results.append(result)

    return jsonify(serialized_results)

if __name__ == "__main__":
    app.secret_key = "this is the session key"
    app.run(debug=True)


from pymongo import MongoClient
import csv
import os
import sys
from flask_bcrypt import Bcrypt

from datetime import datetime, timedelta
import hashlib
import requests
import logging

from flask import Flask, jsonify
from bson import ObjectId
import json  # Import the standard library's json

from datetime import timedelta
from bson import ObjectId, json_util

import traceback
from flask import Flask, render_template, request, jsonify, make_response, flash, redirect, url_for, session
from functools import wraps

# decorator to verify that user is logged in before displaying a page.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function



app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
'''
# Load configuration from config.json
try:
    with open('config.json') as config_file:
        config = json.load(config_file)
        
# Ensure that both SECRET_KEY and MONGO_URI are present in the config
        if 'SECRET_KEY' not in config or 'MONGO_URI' not in config:
            print("Missing required keys in config.json. Exiting.")
            sys.exit(1)
            
        app.config['SECRET_KEY'] = config.get('SECRET_KEY', 'default_secret_key')
        mongo_uri = config.get('MONGO_URI')
except FileNotFoundError:
    print("config.json file not found. Exiting.")
    sys.exit(1)
    
    

# Setup MongoDB connection, this must obviously be running already on localhost for this implementation, but I can change later
client = MongoClient(mongo_uri)
'''

# Load SECRET_KEY and MONGO_URI from environment variables
try:
    secret_key = os.environ['SECRET_KEY']
    mongo_uri = os.environ['MONGO_URI']
    api_key_url = os.environ['API_KEY_URL']
except KeyError as e:
    print(f"Environment variable {e.args[0]} not set. Exiting.")
    sys.exit(1)

app.config['SECRET_KEY'] = secret_key

# Setup MongoDB connection
client = MongoClient(mongo_uri)


# Session security settings, this keeps info in cookies safe
app.config['SESSION_COOKIE_SECURE'] = False  # For development only
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['WTF_CSRF_ENABLED'] = True
# Set the duration for the session data to be stored
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Sessions last for 1 day

bcrypt = Bcrypt(app)#this is for encrypting login information with mongo


# This global variable stores the timestamp of the last failed attempt and the number of failed attempts in the create user route.
cooldown_info = {"last_attempt": None, "failed_attempts": 0}







#I'm having trouble getting this to work correctly, until then, I'm using the json to store the api key
def get_environment_variable(key):
    try:
        # Try to read the environment variable
        value = os.environ[key]
    except KeyError:
        # The environment variable was not found
        print(f"Error: The environment variable {key} was not set.")
        # Handle the error (exit with an error message, or return a default value)
        
        exit(1)  # Exit with a status code indicating an error occurred.
    else:
        return value




#this is to get the database object search working with serializable


class JSONEncoder(json.JSONEncoder):
    ''' extend json-encoder class'''

    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

app.json_encoder = JSONEncoder




db = client["incident_db"]#database name that stores incidents
users_collection = db["users"]#for login info users in database for incidents





# Check if admin exists in users collection
admin_exists = users_collection.find_one({"username": "admin"})
#if not, create one first time
if not admin_exists:
    hashed_password = bcrypt.generate_password_hash("admin").decode('utf-8')
    users_collection.insert_one({"username": "admin", "password": hashed_password, "type": "superuser"})
    

collection = db["incidents"]#collection name
incidents_collection =db["incidents"]

data_list = []# for posting data to the bottom when submit button pressed



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

    # Return a JSON response
    return jsonify({"success": True, "redirect": url_for("login")})



@app.route("/create-user", methods=["GET", "POST"])
# @login_required
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
        
        #Chris added the passkey verification here when create an initial account.
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
# @login_required
def homepage():
    return render_template("homepage.html")

@app.route("/create-incident", methods=["GET"])
@login_required
def create_incident():
    if "username" not in session:
        return redirect(url_for("login"))
    
    # Get incidents from the database
    incidents = db.incidents.find()
    print('Session data at /create-incident:', session.items())
    return render_template("createIncident.html")


# added to link to view incidents page
@app.route("/view-incidents", methods=["GET"])
@login_required
def view_incidents():
    return render_template("viewIncidents.html")


# added to link to view statistics page
@app.route("/view-stats", methods=["GET"])
@login_required
def view_stats():
    return render_template("stats.html")

#Chris added this to view the stats
@app.route('/api/statistics')
def get_statistics():
    
# Aggregation for incidents by date
    date_pipeline = [
        {"$group": {
            "_id": "$date",  # Group directly by the date string
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}  # Sort by date in ascending order
    ]
    incidents_by_date = list(db.incidents.aggregate(date_pipeline))    


    incident_type_pipeline = [
        {"$group": {
            "_id": "$incident_type",
            "count": {"$sum": 1}
        }}
    ]
    incident_types = list(db.incidents.aggregate(incident_type_pipeline))

    # Aggregation for severity
    severity_pipeline = [
        {"$group": {
            "_id": "$severity",
            "count": {"$sum": 1}
        }}
    ]
    severity_data = list(db.incidents.aggregate(severity_pipeline))

    # Aggregation for analyst_name
    analyst_name_pipeline = [
        {"$group": {
            "_id": "$analyst_name",
            "count": {"$sum": 1}
        }}
    ]
    analyst_name_data = list(db.incidents.aggregate(analyst_name_pipeline))

    # Assuming emails_sent is a numeric value; summing it up. I don't think this works correctly
    emails_sent_pipeline = [
        {"$group": {
            "_id": None,  # Grouping all documents together
            "total": {"$sum": "$emails_sent"}
        }}
    ]
    emails_sent_data = list(db.incidents.aggregate(emails_sent_pipeline))

    ##############################TASK STATS

    # Aggregation for task status
    status_pipeline = [
        {"$unwind": "$tasks"},
        {"$group": {
            "_id": "$tasks.status",
            "count": {"$sum": 1}
        }}
    ]
    status_data = list(db.incidents.aggregate(status_pipeline))

    # Aggregation for Assigned_To
    assigned_to_pipeline = [
        {"$unwind": "$tasks"},
        {"$group": {
            "_id": "$tasks.assigned_to",
            "count": {"$sum": 1}
        }}
    ]
    assigned_to_data = list(db.incidents.aggregate(assigned_to_pipeline))

    # Aggregation for Priority
    priority_pipeline = [
        {"$unwind": "$tasks"},
        {"$group": {
            "_id": "$tasks.priority",
            "count": {"$sum": 1}
        }}
    ]
    priority_data = list(db.incidents.aggregate(priority_pipeline))

    # Aggregation for Priority per Assigned_To
    priority_per_assigned_to_pipeline = [
        {"$unwind": "$tasks"},
        {"$group": {
            "_id": {
                "assigned_to": "$tasks.assigned_to",
                "priority": "$tasks.priority"
            },
            "count": {"$sum": 1}
        }}
    ]
    priority_per_assigned_to_data = list(db.incidents.aggregate(priority_per_assigned_to_pipeline))




    return jsonify({
        "incident_types": incident_types,
        "incidents_by_date": incidents_by_date,
        "severity": severity_data,
        "analyst_name": analyst_name_data,
        "emails_sent": emails_sent_data[0]['total'] if emails_sent_data else 0,
        "task_stats": {
            "status": status_data,
            "assigned_to": assigned_to_data,
            "priority": priority_data,
            "priority_per_assigned_to": priority_per_assigned_to_data
        }
    })


# added to display homepage
@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    username = session.get("username", "Guest") #default to guest, but this shouldn't happen
    user_type = session.get("user_type", "analyst")  # Default to 'analyst' if no user type
    return render_template("dashboard.html", username=username, user_type=user_type)

# ------------------------------------------------------------------------

# EDITED Oct. 18th
#for loading index, it displays any data in data list at the bottom when loaded
@app.route("/")
# @login_required
def start():
    return render_template("homepage.html")

# EDITED Oct. 18th
@app.route("/index")
@login_required
def index():
    logging.debug('Session data: %s', session.items())
    print('Session data at /index:', session.items())  # Print directly to the console
    
    if "username" not in session:#check login info
        return redirect(url_for("login"))
    return render_template("createIncident.html", data_list=data_list)


#submit button that will post (display at bottom) the incident data that was entered in all the text boxes
@app.route("/submit", methods=["POST"])
@login_required
def submit_data():
    print('Session data at /submit:', session.items())
    if "username" not in session:
        return redirect(url_for("login"))#call this python function to get the text box data
    
    # Validate the date
    date_str = request.form["date"]
    try:
        # valid_date = datetime.strptime(date_str, '%m-%d-%Y')  # assuming format is MM-DD-YYYY

        # Changed on 11/13
        valid_date = datetime.strptime(date_str, '%Y-%m-%d')  # Date input returns in YYYY-MM-DD format
    except ValueError:
        return "Invalid date format. Expected YYYY-MM-DD.", 400
    
      
    try:
        # -------------------- Changed On November 14th --------------------------------------------
        latest_ticket = db.tickets.find_one(sort=[("ticket_number", -1)]) # Look for the last ticket number created
        new_ticket_number = latest_ticket["ticket_number"] + 1 if latest_ticket else 1

        # ------------------------------------------------------------------------------------------

        # Assuming form data is correct, construct the data dictionary
        # to get number from the form: sanitize_input(request.form["incident_number"])
        data = {
            "incident_number": new_ticket_number,
            "severity": request.form["severity"],
            "date": datetime.strptime(request.form["date"], '%Y-%m-%d'),  # validate and convert date
            "analyst_name": sanitize_input(request.form["analyst_name"]),
            "incident_type": request.form["incident_type"],
            "email_address": request.form["email_address"],
            "subject_line": request.form["subject_line"],
            "urls": request.form["urls"],
            "notes": request.form["notes"],
            "emails_sent": request.form["emails_sent"],
            "replies": request.form["replies"],
            "tasks": [] 
        }


        # Insert data directly into the MongoDB collection
        collection.insert_one(data)

        # Manually serialize the data, including the ObjectId instances
        response_data = json_util.dumps(data)

        # Redirect back to the index with a success message, or wherever appropriate
        flash('Incident submitted successfully!', 'success')  # Flask's flash messaging
        return app.response_class(response=response_data, status=200, mimetype='application/json')

    except Exception as e:
        # Log the error (consider using actual logging instead of print for production applications)
        print(f"An error occurred when submitting the form: {e}")

        # Give a failure message and stay on the form page (or handle error differently)
        flash('An error occurred. Please try again.', 'error')  # Flask's flash messaging
        return redirect(url_for('index'))  # This would typically redirect back to the form submission page



    return redirect(url_for('index'))#basically reload the page on client so they see updated submitted data

# for adding a task to a specific incident id
@app.route('/add-task/<incident_id>', methods=['POST'])
@login_required
def add_task(incident_id):
    try:
        # Convert the incident_id from a string to an ObjectId
        obj_id = ObjectId(incident_id)
    except:
        return make_response("Invalid incident ID format", 400)

    # Extract task details from the form
    status = request.form.get('status')
    assigned_to = request.form.get('assigned_to')
    priority = request.form.get('priority')
    task_notes = request.form.get('task_notes')

     # Find the incident to which the task will be added
    incident = collection.find_one({'_id': obj_id}, {"tasks": 1})  # retrieve only the 'tasks' field

    if not incident:
        return make_response("Incident not found", 404)

    # Calculate the new task number (length of current tasks + 1)
    current_tasks = incident.get('tasks', [])
    new_task_number = len(current_tasks) + 1

    # Create the new task
    new_task = {
        "task_number": new_task_number,
        "status": status,
        "assigned_to": assigned_to,
        "priority": priority,
        "task_notes": task_notes,
    }

    # Add the new task to the incident's list of tasks
    update_result = collection.update_one(
        {'_id': obj_id},
        {'$push': {'tasks': new_task}}
    )

    if update_result.modified_count == 0:
        return make_response("Incident not found or update failed", 404)

    # Redirect to the incident details page or wherever appropriate
    return redirect(url_for('incident_details', incident_id=incident_id))

@app.route('/update-task/<incident_id>', methods=['POST'])
@login_required
def update_task(incident_id):
    try:
        obj_id = ObjectId(incident_id)
    except:
        return make_response("Invalid incident ID format", 400)

    # Extract task details from the form, including the task number
    task_number = int(request.form.get('task_number'))
    status = request.form.get('status')
    assigned_to = request.form.get('assigned_to')
    priority = request.form.get('priority')
    task_notes = request.form.get('task_notes')

    # Update the task within the incident's task list
    update_result = collection.update_one(
        {'_id': obj_id, 'tasks.task_number': task_number},
        {'$set': {
            'tasks.$.status': status,
            'tasks.$.assigned_to': assigned_to,
            'tasks.$.priority': priority,
            'tasks.$.task_notes': task_notes
        }}
    )

    if update_result.modified_count == 0:
        return make_response("Incident not found or update failed", 404)

    return redirect(url_for('incident_details', incident_id=incident_id))


#store data that's display on the bottom of the page in mongo database
@app.route("/export-to-mongo", methods=["GET"])
@login_required
def export_to_mongo():
    if "username" not in session:
        return redirect(url_for("login"))

    if data_list:
        collection.insert_many(data_list)
        #data_list.clear() maybe clear the screen - dunno if I want to do this
    return redirect(url_for('index'))#reload the screen for client


#load data 
@app.route("/load-from-mongo", methods=["GET"])
@login_required
def load_from_mongo():
    if "username" not in session:
        return redirect(url_for("login"))

    global data_list  
    data_list = list(collection.find())#at the moment, this will get all the data in the collection and load it
   # Convert ObjectId fields to strings for JSON serialization
    for item in data_list:
        item['_id'] = str(item['_id'])
    return redirect(url_for('index'))


#When this button is pressed, get all the keys in a list structure and write to csv, then append data in each column
@app.route("/export-to-csv", methods=["GET"])
@login_required
def export_to_csv():
    if "username" not in session:
        return redirect(url_for("login"))

    keys = ["incident_number","severity", "date", "analyst_name", "incident_type", "email_address", "subject_line","urls", "notes", "emails_sent", "replies"]
    mode = 'a' if os.path.exists("data.csv") else 'w'#if file is there append data, otherwise create a new file
    with open("data.csv", mode, newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)#create a dictionary writer to output to csv
        if mode == 'w':  
            dict_writer.writeheader()
        dict_writer.writerows(data_list)
    return "Data exported to CSV!", 200#I need error checking


#this just clears the bottom of the screen data and reloads
@app.route("/clear-data", methods=["GET"])
@login_required
def clear_data():
    if "username" not in session:
        return redirect(url_for("login"))

    data_list.clear()
    return redirect(url_for('index'))
'''
apis for external malware tools below

'''


#urlscan api - description is on their website - at the moment it's getting the key from config.json, I can't get it from the environment variable correctly atm
@app.route("/urlscan", methods=["GET"])
@login_required
def urlscan():
    if "username" not in session:
        return redirect(url_for("login"))

    url = request.args.get('url')
   
    ''' 
    # Load the configuration file
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            api_key_url = config['API_KEY_URL']
    except (FileNotFoundError, KeyError):
        # Handle the case where the file is missing or the key is not present
        return jsonify({"error": "Configuration for API key is missing."}), 500
    '''

    headers = {
        "Content-Type": "application/json",#get json data
        "API-Key": api_key_url
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


    # I might need to add tasks to this
@app.route("/search-database", methods=["POST"])
@login_required
def search_database():
     try:
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
                {"urls": {"$regex": query, "$options": "i"}},
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

        return jsonify(serialized_results)  # This line sends a JSON response
     
     except Exception as e:  # This block catches all exceptions and returns an error response
        print(f"An error occurred: {e}")
        response = jsonify(error=str(e))
        response.status_code = 500
        return response





@app.route('/incident-details/<incident_id>')
@login_required
def incident_details(incident_id):
    try:
        # Convert the incident_id from a string to an ObjectId
        obj_id = ObjectId(incident_id)
    except:
        # If conversion fails, return an error (bad request)
        return make_response("Invalid incident ID format", 400)

    # Fetch the incident from database using the incident_id
    incident = collection.find_one({'_id': obj_id})

    if incident:
        task_keys = {'task_number': 'Task Number', 'status': 'Status', 'assigned_to': 'Assigned To', 'priority': 'Priority', 'task_notes': 'Task Notes'}

        # Render the HTML template and provide the incident data
        return render_template('incident_details.html', incident=incident, task_keys=task_keys)
    else:
        # If no incident is found, might want to redirect to a 404 page or similar
        return make_response("Incident not found", 404)
    
def incident_report_page(incident_id):
    # Assuming ther's an 'incident_details.html' file in a 'templates' folder
    # This will serve the HTML file when navigating to '/incident-report/<incident_id>'
    return render_template('incident_details.html', incident_id=incident_id)




@app.route("/delete-incidents", methods=["POST"])
@login_required
def delete_incidents():
    try:
        if request.is_json:
            incidents_to_delete = request.json.get('ids', [])
            if incidents_to_delete:
                failed_deletions = []
                for str_id in incidents_to_delete:
                    obj_id = ObjectId(str_id)  # This could be a point of failure if str_id is not valid
                    deletion_result = collection.delete_one({'_id': obj_id})

                    if deletion_result.deleted_count == 0:
                        failed_deletions.append(str_id)

                if failed_deletions:
                    return jsonify({'success': False, 'failed_deletions': failed_deletions}), 500
                else:
                    return jsonify({'success': True, 'message': 'Incidents deleted successfully.'}), 200
            else:
                return jsonify({'success': False, 'message': 'No valid IDs received.'}), 400
        else:
            return jsonify({'success': False, 'message': 'Request body must be JSON.'}), 400

    except Exception as e:
        print(f"An error occurred: {e}")  # It might be useful to print the error to the console.
        traceback.print_exc()  # This will print the stack trace, which should help in debugging.
        return jsonify({'success': False, 'message': 'An error occurred while processing your request.'}), 500



    # Convert each MongoDB document to a dictionary that's JSON serializable
    serialized_results = []
    for result in results:
        # Convert ObjectId to string
        if '_id' in result:
            result['_id'] = str(result['_id'])
        serialized_results.append(result)

    return jsonify(serialized_results)

if __name__ == "__main__":
    app.run(debug=True)
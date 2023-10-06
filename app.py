from flask import Flask, render_template, request, jsonify, redirect, url_for
from pymongo import MongoClient
import csv
import os


app = Flask(__name__)

# Setup MongoDB connection, this must obviously be running already on localhost for this implementation, but I can change later
client = MongoClient("mongodb://localhost:27017/")
db = client["incident_db"]#database name
collection = db["incidents"]#collection name

data_list = []# for posting data to the bottom when submit button pressed

API_KEY_URL = "d33fbeaf-3581-46dc-a70c-a42763abc5b7"  #This is the API key for URL scan

@app.route("/")#for loading index, it displays any data in data list at the bottom when loaded
def index():
    return render_template("index.html", data_list=data_list)
#submit button that will post (display at bottom) the incident data that was entered in all the text boxes
@app.route("/submit", methods=["POST"])
def submit_data():#call this python function to get the text box data
    data = {
        "incident_number": request.form["incident_number"],
	"severity": request.form["severity"],  # Adding severity
        "date": request.form["date"],
        "analyst_name": request.form["analyst_name"],
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
    if data_list:
        collection.insert_many(data_list)
        #data_list.clear() maybe clear the screen - dunno if I want to do this
    return redirect(url_for('index'))#reload the screen for client
#load data 
@app.route("/load-from-mongo", methods=["GET"])
def load_from_mongo():
    global data_list  
    data_list = list(collection.find({}, {'_id': 0}))#at the moment, this will get all the data in the collection and load it
    return redirect(url_for('index'))
#When this button is pressed, get all the keys in a list structure and write to csv, then append data in each column
@app.route("/export-to-csv", methods=["GET"])
def export_to_csv():
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
    data_list.clear()
    return redirect(url_for('index'))
'''
apis for external malware tools below

'''
#urlscan api - description is on their website
@app.route("/urlscan", methods=["GET"])
def urlscan():
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

if __name__ == "__main__":
    app.run(debug=True)

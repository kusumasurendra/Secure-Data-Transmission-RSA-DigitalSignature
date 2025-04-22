from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
import folium
from twilio.rest import Client

app = Flask(__name__)

# Sample crime dataset (latitude, longitude, crime score)
crime_data = pd.DataFrame({
    'latitude': [28.7041, 19.0760, 12.9716, 22.5726],
    'longitude': [77.1025, 72.8777, 77.5946, 88.3639],
    'crime_score': [80, 65, 90, 75]
})

# Train anomaly detection model
X = crime_data[['latitude', 'longitude']]
clustering = DBSCAN(eps=0.5, min_samples=2).fit(X)
crime_data['cluster'] = clustering.labels_

def get_risk_score(lat, lon):
    distances = np.sqrt((crime_data['latitude'] - lat)**2 + (crime_data['longitude'] - lon)**2)
    min_distance = distances.min()
    if min_distance < 0.05:
        return "High Risk"
    elif min_distance < 0.1:
        return "Medium Risk"
    return "Low Risk"

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    lat, lon = data['latitude'], data['longitude']
    risk = get_risk_score(lat, lon)
    return jsonify({"risk_level": risk})

@app.route('/send_alert', methods=['POST'])
def send_alert():
    data = request.get_json()
    phone_number = data['phone']
    message = "Emergency Alert! Please help. Location: " + str(data['latitude']) + ", " + str(data['longitude'])
    
    # Twilio Credentials (Replace with actual credentials)
    account_sid = "your_twilio_sid"
    auth_token = "your_twilio_auth_token"
    client = Client(account_sid, auth_token)
    
    client.messages.create(body=message, from_="+1234567890", to=phone_number)
    return jsonify({"status": "Alert Sent"})

if __name__ == '__main__':
    app.run(debug=True)

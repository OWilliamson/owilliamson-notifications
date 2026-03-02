import requests
import json

# Replace these variables with actual values from your environment
priority = "your_priority"
urgency = "your_urgency"
severity = "your_severity"
cat = "your_category"
description = "your_description"
message = "your_message"
email = "caller@example.com"  # Replace with actual email from config

# Construct the incident data payload
incident_data = {
    'IncidentContainerJsonObj': {
        "Updater": "Caller",
        "Ticket": {
            "IsFromWebService": "true",
            "Classification_Name": "Opsview Event",
            "Sup_Function": "MSCW",
            "Caller_EmailID": email,
            "Status": "New",
            "Source": "Opsview",
            "Priority_Name": priority,
            "Urgency_Name": urgency,
            "Assigned_WorkGroup_Name": "Service Desk (Alarms)",
            "Medium": "Application",
            "Impact_Name": severity,
            "Category": cat,
            "OpenCategory": cat,
            "SLA_Name": "24X7",
            "Description": description,
            "PageName": "LogTicket"
        },
        "TicketInformation": {
            "Information": message,
        },
        "CustomFields": [
            {
                "GroupName": "Incident Additional Information",
                "Name": "Affected Service",
                # Add "Value" field if required by API
                # "Value": "Your Service Name"
            }
        ],
    }
}

# API endpoint (replace with actual URL)
api_url = "https://api.example.com/incidents"

# Send POST request
headers = {'Content-Type': 'application/json'}
response = requests.post(
    api_url,
    headers=headers,
    data=json.dumps(incident_data)
)

# Check response status
if response.status_code == 200:
    print("Request successful!")
    print("Response:", response.json())
else:
    print(f"Request failed with status code {response.status_code}")
    print("Response:", response.text)

# Return the response (modify as needed for your use case)
return response.json()

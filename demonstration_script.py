"""
Demonstration script for the Secure Decentralized Audit System
This script automates the demonstration of key features
"""
import os
import json
import time
import subprocess
import threading
import signal
import sys

# Ensure server_data directory exists
os.makedirs("server_data", exist_ok=True)

# Clean up any previous files
for file in ["client_request.json", "server_response.json"]:
    if os.path.exists(file):
        os.remove(file)

# Start server in a separate process
def start_server():
    print("Starting server...")
    server_process = subprocess.Popen(
        ["python", "client_server_stubs.py", "--mode", "server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return server_process

def send_request(request):
    """Send request to server and get response"""
    with open("client_request.json", "w") as f:
        json.dump(request, f, indent=2)
        
    # Wait for response
    max_wait = 10  # seconds
    wait_time = 0
    while not os.path.exists("server_response.json") and wait_time < max_wait:
        time.sleep(0.5)
        wait_time += 0.5
        
    if os.path.exists("server_response.json"):
        with open("server_response.json", "r") as f:
            response = json.load(f)
            
        # Remove response file
        os.remove("server_response.json")
        
        return response
    else:
        return {"status": "error", "message": "Server did not respond"}

def run_demo():
    """Run the full demonstration"""
    print("\n==== SECURE DECENTRALIZED AUDIT SYSTEM DEMONSTRATION ====\n")
    
    # 1. Start server
    server_process = start_server()
    time.sleep(2)  # Give server time to start
    
    try:
        print("\n=== STEP 1: USER REGISTRATION ===")
        print("Registering users: 3 patients, 2 doctors, and 1 administrator")
        
        # Register patients
        for i in range(1, 4):
            request = {
                "type": "register",
                "user_id": f"patient{i}",
                "name": f"Patient {i}",
                "role": "patient"
            }
            response = send_request(request)
            print(f"Registered patient{i}: {response['status']}")
            
        # Register doctors
        for i in range(1, 3):
            request = {
                "type": "register",
                "user_id": f"doctor{i}",
                "name": f"Dr. Smith {i}",
                "role": "doctor"
            }
            response = send_request(request)
            print(f"Registered doctor{i}: {response['status']}")
            
        # Register admin
        request = {
            "type": "register",
            "user_id": "admin1",
            "name": "Admin User",
            "role": "admin"
        }
        response = send_request(request)
        print(f"Registered admin1: {response['status']}")
        
        print("\n=== STEP 2: USER AUTHENTICATION ===")
        print("Logging in as different users")
        
        # Login as a doctor
        request = {
            "type": "login",
            "user_id": "doctor1"
        }
        response = send_request(request)
        doctor_token = response.get("session_token")
        print(f"Doctor1 login: {response['status']}")
        
        # Login as a patient
        request = {
            "type": "login",
            "user_id": "patient1"
        }
        response = send_request(request)
        patient_token = response.get("session_token")
        print(f"Patient1 login: {response['status']}")
        
        # Login as an audit company
        request = {
            "type": "login",
            "user_id": "audit1"
        }
        response = send_request(request)
        audit_token = response.get("session_token")
        print(f"Audit1 login: {response['status']}")
        
        print("\n=== STEP 3: EHR ACCESS AND AUDIT RECORD GENERATION ===")
        print("Doctors accessing patient records")
        
        # Doctor accesses patient records
        actions = ["query", "change", "print"]
        for i, action in enumerate(actions):
            patient_id = f"patient{(i % 3) + 1}"
            request = {
                "type": "access_ehr",
                "session_token": doctor_token,
                "patient_id": patient_id,
                "action_type": action
            }
            response = send_request(request)
            print(f"Doctor accessed {patient_id} record ({action}): {response['status']}")
            time.sleep(1)  # Pause between actions
            
        print("\n=== STEP 4: PATIENT QUERYING THEIR OWN AUDIT RECORDS ===")
        print("Patient1 checking who accessed their records")
        
        # Patient queries their audit records
        request = {
            "type": "query_audit",
            "session_token": patient_token,
            "patient_id": "patient1"
        }
        response = send_request(request)
        
        if response["status"] == "success":
            print("Patient1 successfully queried their audit records")
            records = response.get("records", [])
            print(f"Found {len(records)} audit records for patient1")
            
            # Display a sample record
            if records:
                print("\nSample audit record:")
                record = records[0]
                print(f"  Timestamp: {record.get('timestamp')}")
                print(f"  User ID: {record.get('user_id')}")
                print(f"  Action Type: {record.get('action_type')}")
        else:
            print(f"Patient query failed: {response.get('message')}")
            
        print("\n=== STEP 5: PATIENT ATTEMPTING TO ACCESS ANOTHER PATIENT'S RECORDS ===")
        print("Testing authorization: Patient1 trying to access Patient2's audit records")
        
        # Patient tries to access another patient's audit records (should fail)
        request = {
            "type": "query_audit",
            "session_token": patient_token,
            "patient_id": "patient2"
        }
        response = send_request(request)
        print(f"Patient1 accessing Patient2 records: {response['status']} - {response.get('message')}")
        
        print("\n=== STEP 6: AUDIT COMPANY ACCESSING ALL RECORDS ===")
        print("Audit company querying all patient records")
        
        # Audit company queries all records
        request = {
            "type": "query_audit",
            "session_token": audit_token,
            "query_all": True
        }
        response = send_request(request)
        
        if response["status"] == "success":
            print("Audit company successfully queried all audit records")
            records = response.get("records", [])
            print(f"Found {len(records)} total audit records in the system")
            
            # Group records by patient_id
            by_patient = {}
            for record in records:
                patient_id = record.get("patient_id")
                if patient_id not in by_patient:
                    by_patient[patient_id] = 0
                by_patient[patient_id] += 1
                
            print("\nRecords by patient:")
            for patient_id, count in by_patient.items():
                print(f"  {patient_id}: {count} records")
        else:
            print(f"Audit company query failed: {response.get('message')}")
            
        print("\n=== STEP 7: CHECKING BLOCKCHAIN INTEGRITY ===")
        print("Verifying the integrity of the audit blockchain")
        
        # Check blockchain integrity
        request = {
            "type": "check_integrity"
        }
        response = send_request(request)
        
        print(f"Blockchain integrity check: {response.get('message')}")
        print(f"Blockchain valid: {response.get('blockchain_valid', False)}")
        
        print("\n=== STEP 8: TAMPERING DETECTION DEMONSTRATION ===")
        print("Simulating an attack where someone tries to modify audit records")
        
        # Simulate tampering
        request = {
            "type": "simulate_tampering",
            "block_index": 1,
            "record_index": 0,
            "field": "action_type",
            "new_value": "FAKE_ACTION"
        }
        response = send_request(request)
        
        if response["status"] == "success":
            result = response.get("result", {})
            print(f"Tampering detected: {result.get('detected', False)}")
            print(f"Original value: {result.get('original_value')}")
            print(f"Tampered value: {result.get('new_value')}")
        else:
            print(f"Tampering simulation failed: {response.get('message')}")
            
        # Check blockchain integrity again after tampering
        request = {
            "type": "check_integrity"
        }
        response = send_request(request)
        
        print(f"Blockchain integrity after tampering: {response.get('message')}")
        print(f"Blockchain valid: {response.get('blockchain_valid', False)}")
        
        print("\n=== DEMONSTRATION COMPLETE ===")
        print("The system has successfully demonstrated:")
        print("1. User registration and authentication")
        print("2. Audit record generation during EHR access")
        print("3. Role-based query authorization")
        print("4. Blockchain-based immutability")
        print("5. Tampering detection")
        
    finally:
        print("\nStopping server...")
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    run_demo()
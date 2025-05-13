"""
Client and Server implementation for the Secure Decentralized Audit System
"""
import os
import json
import time
import hashlib
import uuid
import datetime
import base64
import argparse
import pickle
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from system_architecture import (
    User,
    AuthenticationService,
    AuditLogGenerator,
    Blockchain,
    QueryService,
    TamperingDetector,
    PrivacyService,
    EHRSystem
)

# Import our system modules
# In a real implementation, these would be imported from another file
# But for simplicity and the purpose of this project, we assume they're
# already defined (from the previous artifact)

# =============================================
# SERVER IMPLEMENTATION
# =============================================

class AuditServer:
    def __init__(self):
        """Initialize the audit server components"""
        self.auth_service = AuthenticationService()
        self.blockchain = Blockchain(difficulty=2)  # Reduced difficulty for demo
        self.audit_log_generator = AuditLogGenerator(self.auth_service)
        self.query_service = QueryService(self.auth_service, self.blockchain)
        self.tampering_detector = TamperingDetector(self.blockchain)
        self.privacy_service = PrivacyService()
        self.ehr_system = EHRSystem(
            self.auth_service, 
            self.audit_log_generator, 
            self.blockchain, 
            self.query_service
        )
        
        # Add some blockchain nodes for decentralization
        self.blockchain.add_node("http://audit-node1.example.com")
        self.blockchain.add_node("http://audit-node2.example.com")
        self.blockchain.add_node("http://audit-node3.example.com")
        
        # For demonstration, create 3 audit companies
        self._create_audit_companies()
        
        # Directory to store server state (simulate persistence)
        os.makedirs("server_data", exist_ok=True)
        
        # Load server state if exists
        self._load_state()
        
        # Start background mining thread (in a real system, mining would run on nodes)
        self.mining_thread = threading.Thread(target=self._background_mining)
        self.mining_thread.daemon = True
        self.mining_thread.start()
        
    def _create_audit_companies(self):
        """Create audit companies for the demo"""
        for i in range(1, 4):
            audit_company = User(
                f"audit{i}",
                f"Audit Company {i}",
                "audit_company"
            )
            self.auth_service.register_user(audit_company)
    
    def handle_request(self, request):
        """Process client requests"""
        request_type = request.get("type")
        
        if request_type == "register":
            return self._handle_register(request)
        elif request_type == "login":
            return self._handle_login(request)
        elif request_type == "access_ehr":
            return self._handle_access_ehr(request)
        elif request_type == "query_audit":
            return self._handle_query_audit(request)
        elif request_type == "check_integrity":
            return self._handle_check_integrity()
        elif request_type == "simulate_tampering":
            return self._handle_simulate_tampering(request)
        else:
            return {"status": "error", "message": "Unknown request type"}
            
    def _handle_register(self, request):
        """Handle user registration"""
        user_id = request.get("user_id")
        name = request.get("name")
        role = request.get("role")
        
        if not all([user_id, name, role]):
            return {"status": "error", "message": "Missing required fields"}
            
        if role not in ["patient", "doctor", "admin", "audit_company"]:
            return {"status": "error", "message": "Invalid role"}
            
        user = User(user_id, name, role)
        self.auth_service.register_user(user)
        
        # Save server state
        self._save_state()
        
        return {
            "status": "success", 
            "message": f"User {name} registered as {role}",
            "public_key": user.get_public_key_pem().decode()
        }
        
    def _handle_login(self, request):
        """Handle user login"""
        user_id = request.get("user_id")
        
        if not user_id:
            return {"status": "error", "message": "Missing user ID"}
            
        # In a real system, we'd verify signatures
        # Here, we simplify for demonstration
        success, result = self.auth_service.authenticate(user_id, "signature", "challenge")
        
        if not success:
            return {"status": "error", "message": result}
            
        return {
            "status": "success",
            "message": "Authentication successful",
            "session_token": result
        }
        
    def _handle_access_ehr(self, request):
        """Handle EHR access"""
        session_token = request.get("session_token")
        patient_id = request.get("patient_id")
        action_type = request.get("action_type")
        
        if not all([session_token, patient_id, action_type]):
            return {"status": "error", "message": "Missing required fields"}
            
        success, result = self.ehr_system.access_patient_record(
            session_token, patient_id, action_type
        )
        
        if not success:
            return {"status": "error", "message": result}
            
        # Save server state
        self._save_state()
        
        return {"status": "success", "message": result}
        
    def _handle_query_audit(self, request):
        """Handle audit query"""
        session_token = request.get("session_token")
        patient_id = request.get("patient_id")
        query_all = request.get("query_all", False)
        
        if not session_token:
            return {"status": "error", "message": "Missing session token"}
            
        if query_all:
            success, result = self.query_service.query_all_records(session_token)
        else:
            if not patient_id:
                return {"status": "error", "message": "Missing patient ID"}
                
            success, result = self.query_service.query_patient_records(
                session_token, patient_id
            )
            
        if not success:
            return {"status": "error", "message": result}
            
        # In a real system, we might encrypt sensitive information
        # before returning it to the client
        return {
            "status": "success",
            "message": "Query successful",
            "records": result
        }
        
    def _handle_check_integrity(self):
        """Check blockchain integrity"""
        success, message = self.tampering_detector.detect_tampering()
        
        return {
            "status": "success" if success else "error",
            "message": message,
            "blockchain_valid": success
        }
        
    def _handle_simulate_tampering(self, request):
        """Simulate tampering with audit data"""
        block_index = request.get("block_index", 1)
        record_index = request.get("record_index", 0)
        field = request.get("field", "action_type")
        new_value = request.get("new_value", "TAMPERED_VALUE")
        
        success, result = self.tampering_detector.simulate_tampering(
            block_index, record_index, field, new_value
        )
        
        if not success:
            return {"status": "error", "message": result}
            
        return {
            "status": "success",
            "message": "Tampering simulation complete",
            "result": result
        }
        
    def _background_mining(self):
        """Background thread to periodically mine pending records"""
        while True:
            if len(self.blockchain.pending_records) > 0:
                self.blockchain.mine_pending_records("system_reward_address")
                self._save_state()
            time.sleep(30)  # Mine every 30 seconds if there are pending records
            
    def _save_state(self):
        """Save server state to simulate persistence"""
        try:
            with open("server_data/blockchain.pkl", "wb") as f:
                pickle.dump(self.blockchain, f)
                
            with open("server_data/auth_service.pkl", "wb") as f:
                pickle.dump(self.auth_service, f)
        except Exception as e:
            print(f"Error saving state: {e}")
            
    def _load_state(self):
        """Load server state if available"""
        try:
            if os.path.exists("server_data/blockchain.pkl"):
                with open("server_data/blockchain.pkl", "rb") as f:
                    self.blockchain = pickle.load(f)
                    
            if os.path.exists("server_data/auth_service.pkl"):
                with open("server_data/auth_service.pkl", "rb") as f:
                    self.auth_service = pickle.load(f)
        except Exception as e:
            print(f"Error loading state: {e}")
            print("Starting with fresh state")

def run_server():
    """Run the audit server"""
    server = AuditServer()
    
    print("Audit Server started")
    print("Listening for requests...")
    
    # In a real implementation, this would be a web server
    # For demonstration, we read requests from a file
    
    while True:
        try:
            if os.path.exists("client_request.json"):
                with open("client_request.json", "r") as f:
                    request = json.load(f)
                    
                # Process the request
                response = server.handle_request(request)
                
                # Write response
                with open("server_response.json", "w") as f:
                    json.dump(response, f, indent=2)
                    
                # Delete request file
                os.remove("client_request.json")
                
                print(f"Processed request: {request['type']}")
        except Exception as e:
            print(f"Error processing request: {e}")
            
        time.sleep(1)  # Check for new requests every second

# =============================================
# CLIENT IMPLEMENTATION
# =============================================

class AuditClient:
    def __init__(self):
        """Initialize the audit client"""
        self.session_token = None
        self.user_id = None
        self.role = None
        
    def register(self, user_id, name, role):
        """Register a new user"""
        request = {
            "type": "register",
            "user_id": user_id,
            "name": name,
            "role": role
        }
        
        response = self._send_request(request)
        
        if response["status"] == "success":
            print(f"Registration successful: {response['message']}")
            return True
        else:
            print(f"Registration failed: {response['message']}")
            return False
            
    def login(self, user_id):
        """Log in as a user"""
        request = {
            "type": "login",
            "user_id": user_id
        }
        
        response = self._send_request(request)
        
        if response["status"] == "success":
            self.session_token = response["session_token"]
            self.user_id = user_id
            print(f"Login successful. Session token: {self.session_token}")
            return True
        else:
            print(f"Login failed: {response['message']}")
            return False
            
    def access_patient_record(self, patient_id, action_type):
        """Access a patient record"""
        if not self.session_token:
            print("Not logged in")
            return False
            
        request = {
            "type": "access_ehr",
            "session_token": self.session_token,
            "patient_id": patient_id,
            "action_type": action_type
        }
        
        response = self._send_request(request)
        
        if response["status"] == "success":
            print(f"Record access successful: {response['message']}")
            return True
        else:
            print(f"Record access failed: {response['message']}")
            return False
            
    def query_patient_audit(self, patient_id):
        """Query audit records for a patient"""
        if not self.session_token:
            print("Not logged in")
            return False
            
        request = {
            "type": "query_audit",
            "session_token": self.session_token,
            "patient_id": patient_id
        }
        
        response = self._send_request(request)
        
        if response["status"] == "success":
            print("Query successful")
            self._display_records(response["records"])
            return True
        else:
            print(f"Query failed: {response['message']}")
            return False
            
    def query_all_audits(self):
        """Query all audit records (audit companies only)"""
        if not self.session_token:
            print("Not logged in")
            return False
            
        request = {
            "type": "query_audit",
            "session_token": self.session_token,
            "query_all": True
        }
        
        response = self._send_request(request)
        
        if response["status"] == "success":
            print("Query successful")
            self._display_records(response["records"])
            return True
        else:
            print(f"Query failed: {response['message']}")
            return False
            
    def check_blockchain_integrity(self):
        """Check the integrity of the blockchain"""
        request = {
            "type": "check_integrity"
        }
        
        response = self._send_request(request)
        
        print(f"Blockchain integrity: {response['message']}")
        print(f"Valid: {response.get('blockchain_valid', False)}")
        return response.get('blockchain_valid', False)
        
    def simulate_tampering(self, block_index=1, record_index=0):
        """Simulate tampering with audit data"""
        request = {
            "type": "simulate_tampering",
            "block_index": block_index,
            "record_index": record_index,
            "field": "action_type",
            "new_value": "TAMPERED_VALUE"
        }
        
        response = self._send_request(request)
        
        if response["status"] == "success":
            print("Tampering simulation results:")
            print(f"  Tampering detected: {response['result']['detected']}")
            print(f"  Message: {response['result']['message']}")
            print(f"  Tampered block: {response['result']['tampered_block']}")
            print(f"  Tampered record: {response['result']['tampered_record']}")
            print(f"  Field: {response['result']['tampered_field']}")
            print(f"  Original value: {response['result']['original_value']}")
            print(f"  New value: {response['result']['new_value']}")
            return True
        else:
            print(f"Tampering simulation failed: {response['message']}")
            return False
            
    def _send_request(self, request):
        """Send request to server"""
        try:
            # In a real implementation, this would use HTTP
            # For demonstration, we write to a file
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
        except Exception as e:
            return {"status": "error", "message": str(e)}
            
    def _display_records(self, records):
        """Display audit records in a readable format"""
        if not records:
            print("No records found")
            return
            
        print(f"Found {len(records)} audit records:")
        for i, record in enumerate(records):
            print(f"\nRecord #{i+1}:")
            print(f"  ID: {record.get('record_id')}")
            print(f"  Timestamp: {record.get('timestamp')}")
            print(f"  Patient ID: {record.get('patient_id')}")
            print(f"  User ID: {record.get('user_id')}")
            print(f"  User Role: {record.get('user_role')}")
            print(f"  Action Type: {record.get('action_type')}")
            
def run_client():
    """Run the client with a simple CLI"""
    client = AuditClient()
    
    while True:
        print("\n=== Secure Decentralized Audit System Client ===")
        print("1. Register")
        print("2. Login")
        print("3. Access patient record")
        print("4. Query patient audit")
        print("5. Query all audits (audit companies only)")
        print("6. Check blockchain integrity")
        print("7. Simulate tampering (demonstration only)")
        print("8. Exit")
        
        choice = input("Enter your choice (1-8): ")
        
        if choice == "1":
            user_id = input("Enter user ID: ")
            name = input("Enter name: ")
            print("Available roles: patient, doctor, admin, audit_company")
            role = input("Enter role: ")
            client.register(user_id, name, role)
        elif choice == "2":
            user_id = input("Enter user ID: ")
            client.login(user_id)
        elif choice == "3":
            patient_id = input("Enter patient ID: ")
            print("Available actions: create, delete, change, query, print, copy")
            action_type = input("Enter action type: ")
            client.access_patient_record(patient_id, action_type)
        elif choice == "4":
            patient_id = input("Enter patient ID: ")
            client.query_patient_audit(patient_id)
        elif choice == "5":
            client.query_all_audits()
        elif choice == "6":
            client.check_blockchain_integrity()
        elif choice == "7":
            block_index = int(input("Enter block index: "))
            record_index = int(input("Enter record index: "))
            client.simulate_tampering(block_index, record_index)
        elif choice == "8":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

# =============================================
# MAIN EXECUTION
# =============================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Decentralized Audit System")
    parser.add_argument("--mode", choices=["client", "server"], required=True,
                      help="Run in client or server mode")
    
    args = parser.parse_args()
    
    if args.mode == "server":
        run_server()
    else:
        run_client()
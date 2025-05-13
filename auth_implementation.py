"""
Advanced Authentication and Authorization System for EHR Audit
Implements role-based access control with public key infrastructure
"""
import os
import json
import time
import datetime
import uuid
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import jwt  # For JSON Web Tokens

# Role definitions with hierarchical permissions
ROLES = {
    "patient": {
        "permissions": ["view_own_records", "query_own_audit"]
    },
    "doctor": {
        "permissions": ["view_patient_records", "modify_patient_records", 
                       "view_own_audit"]
    },
    "admin": {
        "permissions": ["view_all_records", "modify_all_records", 
                       "user_management"]
    },
    "audit_company": {
        "permissions": ["view_all_audit", "query_all_audit", 
                       "verify_blockchain"]
    }
}

class KeyManager:
    """
    Manages cryptographic keys for users and the system
    """
    def __init__(self):
        self.key_store_dir = "key_store"
        os.makedirs(self.key_store_dir, exist_ok=True)
        
        # Generate system keys if they don't exist
        self._ensure_system_keys()
        
    def _ensure_system_keys(self):
        """Generate system keys if not already present"""
        system_private_key_path = os.path.join(self.key_store_dir, "system_private_key.pem")
        system_public_key_path = os.path.join(self.key_store_dir, "system_public_key.pem")
        
        if not os.path.exists(system_private_key_path):
            # Generate a new RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Save private key
            with open(system_private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            # Save public key
            public_key = private_key.public_key()
            with open(system_public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
                
            print("Generated new system key pair")
            
    def generate_user_keys(self, user_id):
        """Generate a new key pair for a user"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create user directory
        user_dir = os.path.join(self.key_store_dir, user_id)
        os.makedirs(user_dir, exist_ok=True)
        
        # Save private key
        private_key_path = os.path.join(user_dir, "private_key.pem")
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Save public key
        public_key = private_key.public_key()
        public_key_path = os.path.join(user_dir, "public_key.pem")
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
        return {
            "private_key_pem": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "public_key_pem": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }
        
    def get_user_public_key(self, user_id):
        """Get a user's public key"""
        public_key_path = os.path.join(self.key_store_dir, user_id, "public_key.pem")
        
        if not os.path.exists(public_key_path):
            return None
            
        with open(public_key_path, "rb") as f:
            public_key_pem = f.read()
            
        return public_key_pem
        
    def get_user_private_key(self, user_id):
        """Get a user's private key (in a real system, this would never be exposed)"""
        private_key_path = os.path.join(self.key_store_dir, user_id, "private_key.pem")
        
        if not os.path.exists(private_key_path):
            return None
            
        with open(private_key_path, "rb") as f:
            private_key_pem = f.read()
            
        return private_key_pem
        
    def get_system_public_key(self):
        """Get the system's public key"""
        public_key_path = os.path.join(self.key_store_dir, "system_public_key.pem")
        
        with open(public_key_path, "rb") as f:
            public_key_pem = f.read()
            
        return public_key_pem
        
    def get_system_private_key(self):
        """Get the system's private key"""
        private_key_path = os.path.join(self.key_store_dir, "system_private_key.pem")
        
        with open(private_key_path, "rb") as f:
            private_key_pem = f.read()
            
        return private_key_pem
        
    def sign_data(self, data, private_key_pem=None):
        """
        Sign data with a private key
        If private_key_pem is None, uses the system private key
        """
        if private_key_pem is None:
            private_key_pem = self.get_system_private_key()
            
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode()
        
    def verify_signature(self, data, signature, public_key_pem=None):
        """
        Verify a signature using a public key
        If public_key_pem is None, uses the system public key
        """
        if public_key_pem is None:
            public_key_pem = self.get_system_public_key()
            
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        signature_bytes = base64.b64decode(signature)
        
        try:
            public_key.verify(
                signature_bytes,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
            
class UserStore:
    """
    Stores and manages user information
    """
    def __init__(self, key_manager):
        self.key_manager = key_manager
        self.users_dir = "users"
        os.makedirs(self.users_dir, exist_ok=True)
        
    def create_user(self, user_id, name, role, email=None, organization=None):
        """Create a new user"""
        if role not in ROLES:
            return False, f"Invalid role: {role}"
            
        # Check if user already exists
        user_path = os.path.join(self.users_dir, f"{user_id}.json")
        if os.path.exists(user_path):
            return False, f"User {user_id} already exists"
            
        # Generate keys for the user
        keys = self.key_manager.generate_user_keys(user_id)
        
        # Create user record
        user = {
            "user_id": user_id,
            "name": name,
            "role": role,
            "email": email,
            "organization": organization,
            "permissions": ROLES[role]["permissions"],
            "public_key": keys["public_key_pem"].decode(),
            "created_at": datetime.datetime.now().isoformat(),
            "status": "active"
        }
        
        # Save user
        with open(user_path, "w") as f:
            json.dump(user, f, indent=2)
            
        return True, user
        
    def get_user(self, user_id):
        """Get user details"""
        user_path = os.path.join(self.users_dir, f"{user_id}.json")
        
        if not os.path.exists(user_path):
            return None
            
        with open(user_path, "r") as f:
            user = json.load(f)
            
        return user
        
    def update_user(self, user_id, updates):
        """Update user details"""
        user = self.get_user(user_id)
        
        if user is None:
            return False, f"User {user_id} not found"
            
        # Apply updates
        for key, value in updates.items():
            if key in ["user_id", "public_key", "created_at"]:
                continue  # These fields cannot be updated
                
            if key == "role" and value in ROLES:
                user[key] = value
                user["permissions"] = ROLES[value]["permissions"]
            elif key != "permissions":  # Don't allow direct permission updates
                user[key] = value
                
        # Save updated user
        user_path = os.path.join(self.users_dir, f"{user_id}.json")
        with open(user_path, "w") as f:
            json.dump(user, f, indent=2)
            
        return True, user
        
    def deactivate_user(self, user_id):
        """Deactivate a user"""
        return self.update_user(user_id, {"status": "inactive"})
        
    def activate_user(self, user_id):
        """Activate a user"""
        return self.update_user(user_id, {"status": "active"})
        
    def list_users(self, role=None, status="active"):
        """List all users, optionally filtered by role and status"""
        users = []
        
        for filename in os.listdir(self.users_dir):
            if filename.endswith(".json"):
                with open(os.path.join(self.users_dir, filename), "r") as f:
                    user = json.load(f)
                    
                    if (role is None or user["role"] == role) and (status is None or user["status"] == status):
                        users.append(user)
                        
        return users

class AuthenticationService:
    """
    Handles user authentication and session management
    """
    def __init__(self, user_store, key_manager):
        self.user_store = user_store
        self.key_manager = key_manager
        self.sessions = {}
        self.jwt_secret = os.urandom(32)  # In a real system, this would be persistent
        self.challenge_store = {}
        
    def generate_challenge(self, user_id):
        """Generate a challenge for authentication"""
        challenge = os.urandom(32).hex()
        expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)
        
        self.challenge_store[user_id] = {
            "challenge": challenge,
            "expiry": expiry
        }
        
        return challenge
        
    def verify_challenge_response(self, user_id, challenge, signature):
        """Verify a challenge response for authentication"""
        if user_id not in self.challenge_store:
            return False, "No challenge found for user"
            
        stored_challenge = self.challenge_store[user_id]
        
        # Check if challenge has expired
        if datetime.datetime.now() > stored_challenge["expiry"]:
            del self.challenge_store[user_id]
            return False, "Challenge expired"
            
        # Check if challenge matches
        if challenge != stored_challenge["challenge"]:
            return False, "Challenge mismatch"
            
        # Get user's public key
        user = self.user_store.get_user(user_id)
        if user is None:
            return False, "User not found"
            
        if user["status"] != "active":
            return False, "User is not active"
            
        # Verify signature
        public_key_pem = user["public_key"].encode()
        
        if not self.key_manager.verify_signature(challenge, signature, public_key_pem):
            return False, "Invalid signature"
            
        # Challenge verified, remove from store
        del self.challenge_store[user_id]
        
        return True, "Challenge verified"
        
    def login(self, user_id, signature, challenge):
        """Authenticate user and create session"""
        # Verify challenge
        challenge_verified, message = self.verify_challenge_response(user_id, challenge, signature)
        
        if not challenge_verified:
            return False, message
            
        # Get user
        user = self.user_store.get_user(user_id)
        
        # Create session token (JWT)
        session_token = self._create_session_token(user)
        
        return True, {
            "session_token": session_token,
            "user_id": user_id,
            "role": user["role"],
            "permissions": user["permissions"]
        }
        
    def _create_session_token(self, user):
        """Create a JWT session token"""
        expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        
        payload = {
            "sub": user["user_id"],
            "name": user["name"],
            "role": user["role"],
            "permissions": user["permissions"],
            "exp": expiry,
            "iat": datetime.datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        
        # Store session
        self.sessions[token] = {
            "user_id": user["user_id"],
            "expiry": expiry
        }
        
        return token
        
    def validate_session(self, session_token):
        """Validate a session token"""
        try:
            # Decode and validate JWT
            payload = jwt.decode(session_token, self.jwt_secret, algorithms=["HS256"])
            
            # Check if session exists
            if session_token not in self.sessions:
                return False, "Session not found"
                
            # Check if session has expired
            session = self.sessions[session_token]
            if datetime.datetime.utcnow() > session["expiry"]:
                del self.sessions[session_token]
                return False, "Session expired"
                
            # Get user
            user = self.user_store.get_user(payload["sub"])
            if user is None:
                return False, "User not found"
                
            if user["status"] != "active":
                return False, "User is not active"
                
            return True, user
            
        except jwt.ExpiredSignatureError:
            return False, "Session expired"
        except jwt.InvalidTokenError:
            return False, "Invalid session token"
            
    def logout(self, session_token):
        """Invalidate a session token"""
        if session_token in self.sessions:
            del self.sessions[session_token]
            
        return True, "Logged out successfully"
    
    def refresh_session(self, session_token):
        """Refresh a session token"""
        valid, user_or_message = self.validate_session(session_token)
        
        if not valid:
            return False, user_or_message
            
        # Invalidate old session
        self.logout(session_token)
        
        # Create new session
        new_token = self._create_session_token(user_or_message)
        
        return True, {
            "session_token": new_token,
            "user_id": user_or_message["user_id"],
            "role": user_or_message["role"],
            "permissions": user_or_message["permissions"]
        }

class AuthorizationService:
    """
    Handles authorization decisions based on user roles and permissions
    """
    def __init__(self, auth_service):
        self.auth_service = auth_service
        
    def check_permission(self, session_token, required_permission):
        """Check if user has a specific permission"""
        valid, user_or_message = self.auth_service.validate_session(session_token)
        
        if not valid:
            return False, user_or_message
            
        user = user_or_message
        
        if required_permission in user["permissions"]:
            return True, user
        else:
            return False, "Permission denied"
            
    def can_access_patient_records(self, session_token, patient_id):
        """Check if user can access a specific patient's records"""
        valid, user_or_message = self.auth_service.validate_session(session_token)
        
        if not valid:
            return False, user_or_message
            
        user = user_or_message
        
        # Patients can only access their own records
        if user["role"] == "patient":
            if str(user["user_id"]) == str(patient_id):
                return True, user
            else:
                return False, "Patients can only access their own records"
                
        # Doctors can access any patient's records
        elif user["role"] == "doctor" and "view_patient_records" in user["permissions"]:
            return True, user
            
        # Admins can access all records
        elif user["role"] == "admin" and "view_all_records" in user["permissions"]:
            return True, user
            
        # Audit companies can access audit records, not patient records
        elif user["role"] == "audit_company":
            return False, "Audit companies cannot access patient records"
            
        return False, "Permission denied"
        
    def can_modify_patient_records(self, session_token, patient_id):
        """Check if user can modify a specific patient's records"""
        valid, user_or_message = self.auth_service.validate_session(session_token)
        
        if not valid:
            return False, user_or_message
            
        user = user_or_message
        
        # Patients cannot modify records
        if user["role"] == "patient":
            return False, "Patients cannot modify records"
                
        # Doctors can modify patient records
        elif user["role"] == "doctor" and "modify_patient_records" in user["permissions"]:
            return True, user
            
        # Admins can modify all records
        elif user["role"] == "admin" and "modify_all_records" in user["permissions"]:
            return True, user
            
        return False, "Permission denied"
        
    def can_query_audit_records(self, session_token, patient_id=None):
        """Check if user can query audit records"""
        valid, user_or_message = self.auth_service.validate_session(session_token)
        
        if not valid:
            return False, user_or_message
            
        user = user_or_message
        
        # Patients can query their own audit records
        if user["role"] == "patient":
            if patient_id is None or user["user_id"] == patient_id:
                return True, user
            else:
                return False, "Patients can only query their own audit records"
                
        # Doctors can query their own audit activities
        elif user["role"] == "doctor" and "view_own_audit" in user["permissions"]:
            return True, user
            
        # Admins can query all audit records
        elif user["role"] == "admin" and "view_all_records" in user["permissions"]:
            return True, user
            
        # Audit companies can query all audit records
        elif user["role"] == "audit_company" and "view_all_audit" in user["permissions"]:
            return True, user
            
        return False, "Permission denied"
        
    def can_manage_users(self, session_token):
        """Check if user can manage other users"""
        return self.check_permission(session_token, "user_management")
        
    def can_verify_blockchain(self, session_token):
        """Check if user can verify the blockchain"""
        return self.check_permission(session_token, "verify_blockchain")

# Access Manager for EHR Data Access Control
class EHRAccessManager:
    """
    Manages access control for EHR data
    Generates audit records when EHR data is accessed
    """
    def __init__(self, auth_service, auth_manager, key_manager):
        self.auth_service = auth_service
        self.auth_manager = auth_manager
        self.key_manager = key_manager
        
    def access_patient_record(self, session_token, patient_id, action_type, record_id=None):
        """
        Access a patient's record and generate audit record
        
        Args:
            session_token: Active session token
            patient_id: ID of the patient
            action_type: Type of action (create, delete, change, query, print, copy)
            record_id: Optional specific record ID
            
        Returns:
            tuple: (success, result)
                - If success is True, result is the audit record
                - If success is False, result is an error message
        """
        # Check authorization
        can_access, user_or_msg = self.auth_manager.can_access_patient_records(
            session_token, patient_id
        )
        
        if not can_access:
            return False, user_or_msg
            
        user = user_or_msg
        
        # For modify operations, check additional permissions
        if action_type in ["create", "delete", "change"]:
            can_modify, user_or_msg = self.auth_manager.can_modify_patient_records(
                session_token, patient_id
            )
            
            if not can_modify:
                return False, user_or_msg
                
        # Create audit record
        audit_record = self._create_audit_record(
            user["user_id"], 
            user["role"], 
            patient_id, 
            action_type,
            record_id
        )
        
        # Sign the audit record
        private_key_pem = self.key_manager.get_system_private_key()
        signature = self.key_manager.sign_data(audit_record, private_key_pem)
        
        audit_record["signature"] = signature
        
        return True, audit_record
        
    def _create_audit_record(self, user_id, user_role, patient_id, action_type, record_id=None):
        """Create an audit record for EHR access"""
        timestamp = datetime.datetime.now().isoformat()
        record_id = record_id or str(uuid.uuid4())
        
        record = {
            "record_id": record_id,
            "timestamp": timestamp,
            "patient_id": patient_id,
            "user_id": user_id,
            "user_role": user_role,
            "action_type": action_type,
            "data": {}  # Additional data could be added here
        }
        
        return record

# Complete Authentication and Authorization Manager
class AuthManager:
    """
    Central manager for all authentication and authorization functions
    """
    def __init__(self):
        # Initialize components
        self.key_manager = KeyManager()
        self.user_store = UserStore(self.key_manager)
        self.auth_service = AuthenticationService(self.user_store, self.key_manager)
        self.auth_manager = AuthorizationService(self.auth_service)
        self.access_manager = EHRAccessManager(
            self.auth_service, 
            self.auth_manager, 
            self.key_manager
        )
        
        # Create default users if they don't exist
        self._create_default_users()
        
    def _create_default_users(self):
        """Create default users for demonstration"""
        default_users = [
            {
                "user_id": "admin1",
                "name": "Admin User",
                "role": "admin",
                "email": "admin@example.com"
            },
            {
                "user_id": "audit1",
                "name": "Audit Company 1",
                "role": "audit_company",
                "organization": "Audit Co."
            },
            {
                "user_id": "audit2",
                "name": "Audit Company 2",
                "role": "audit_company",
                "organization": "Compliance Inc."
            },
            {
                "user_id": "audit3",
                "name": "Audit Company 3",
                "role": "audit_company",
                "organization": "SecureAudit LLC"
            }
        ]
        
        for user in default_users:
            # Check if user exists
            existing_user = self.user_store.get_user(user["user_id"])
            if existing_user is None:
                print(f"Creating default user: {user['name']} ({user['role']})")
                self.user_store.create_user(
                    user["user_id"],
                    user["name"],
                    user["role"],
                    user.get("email"),
                    user.get("organization")
                )
                
    def register_user(self, user_id, name, role, email=None, organization=None):
        """Register a new user"""
        return self.user_store.create_user(user_id, name, role, email, organization)
        
    def login(self, user_id, challenge=None, signature=None):
        """
        Login a user
        
        If challenge and signature are None, generates a new challenge
        Otherwise, verifies the challenge and signature
        """
        if challenge is None or signature is None:
            # Generate challenge
            challenge = self.auth_service.generate_challenge(user_id)
            return True, {"challenge": challenge}
            
        # Verify challenge and login
        return self.auth_service.login(user_id, signature, challenge)
        
    def validate_session(self, session_token):
        """Validate a session token"""
        return self.auth_service.validate_session(session_token)
        
    def logout(self, session_token):
        """Logout a user"""
        return self.auth_service.logout(session_token)
        
    def check_permission(self, session_token, permission):
        """Check if user has a specific permission"""
        return self.auth_manager.check_permission(session_token, permission)
        
    def access_patient_record(self, session_token, patient_id, action_type, record_id=None):
        """Access a patient record and generate audit"""
        return self.access_manager.access_patient_record(
            session_token, patient_id, action_type, record_id
        )
        
    def can_query_audit_records(self, session_token, patient_id=None):
        """Check if user can query audit records"""
        return self.auth_manager.can_query_audit_records(session_token, patient_id)
        
    def get_user_info(self, session_token):
        """Get information about the logged in user"""
        valid, user_or_message = self.auth_service.validate_session(session_token)
        
        if not valid:
            return False, user_or_message
            
        return True, {
            "user_id": user_or_message["user_id"],
            "name": user_or_message["name"],
            "role": user_or_message["role"],
            "permissions": user_or_message["permissions"]
        }

# Demo function to show authentication and authorization flow
def demo_auth_flow():
    """Demonstrate the authentication and authorization flow"""
    print("\n=== Authentication and Authorization Flow Demo ===\n")
    
    # Initialize auth manager
    auth_manager = AuthManager()
    
    # Step 1: Register users
    print("Step 1: Register users")
    
    # Register patient
    success, result = auth_manager.register_user(
        "patient1", "John Doe", "patient", "john@example.com"
    )
    print(f"Register patient: {'Success' if success else 'Failed'} - {result}")
    
    # Register doctor
    success, result = auth_manager.register_user(
        "doctor1", "Dr. Smith", "doctor", "drsmith@example.com"
    )
    print(f"Register doctor: {'Success' if success else 'Failed'} - {result}")
    
    # Step 2: Login flow
    print("\nStep 2: Login flow")
    
    # Generate challenge
    success, result = auth_manager.login("patient1")
    challenge = result["challenge"]
    print(f"Generated challenge for patient1: {challenge}")
    
    # In a real system, the client would sign the challenge with their private key
    # Here we simulate this by directly getting the private key
    private_key_pem = auth_manager.key_manager.get_user_private_key("patient1")
    signature = auth_manager.key_manager.sign_data(challenge, private_key_pem)
    
    # Complete login
    success, result = auth_manager.login("patient1", challenge, signature)
    if success:
        session_token = result["session_token"]
        print(f"Login successful, received session token: {session_token[:20]}...")
    else:
        print(f"Login failed: {result}")
        return
        
    # Step 3: Access patient record
    print("\nStep 3: Patient accessing their own record")
    success, result = auth_manager.access_patient_record(
        session_token, "patient1", "query"
    )
    print(f"Patient accessing own record: {'Success' if success else 'Failed'}")
    if success:
        print(f"Generated audit record: {result['record_id']}")
        
    # Try to access another patient's record (should fail)
    print("\nStep 3.1: Patient trying to access another patient's record")
    success, result = auth_manager.access_patient_record(
        session_token, "patient2", "query"
    )
    print(f"Patient accessing other patient's record: {'Success' if success else 'Failed'}")
    print(f"Result: {result}")
    
    # Step 4: Login as doctor
    print("\nStep 4: Login as doctor")
    success, result = auth_manager.login("doctor1")
    challenge = result["challenge"]
    
    private_key_pem = auth_manager.key_manager.get_user_private_key("doctor1")
    signature = auth_manager.key_manager.sign_data(challenge, private_key_pem)
    
    success, result = auth_manager.login("doctor1", challenge, signature)
    if success:
        doctor_token = result["session_token"]
        print(f"Doctor login successful, received session token: {doctor_token[:20]}...")
    else:
        print(f"Doctor login failed: {result}")
        return
        
    # Step 5: Doctor accesses patient record
    print("\nStep 5: Doctor accessing patient record")
    success, result = auth_manager.access_patient_record(
        doctor_token, "patient1", "change"
    )
    print(f"Doctor accessing patient record: {'Success' if success else 'Failed'}")
    if success:
        print(f"Generated audit record: {result['record_id']}")
        
    # Step 6: Login as audit company
    print("\nStep 6: Login as audit company")
    success, result = auth_manager.login("audit1")
    challenge = result["challenge"]
    
    private_key_pem = auth_manager.key_manager.get_user_private_key("audit1")
    signature = auth_manager.key_manager.sign_data(challenge, private_key_pem)
    
    success, result = auth_manager.login("audit1", challenge, signature)
    if success:
        audit_token = result["session_token"]
        print(f"Audit company login successful, received session token: {audit_token[:20]}...")
    else:
        print(f"Audit company login failed: {result}")
        return
        
    # Step 7: Audit company checks permissions
    print("\nStep 7: Checking audit company permissions")
    success, result = auth_manager.check_permission(audit_token, "view_all_audit")
    print(f"Audit company has 'view_all_audit' permission: {'Yes' if success else 'No'}")
    
    success, result = auth_manager.check_permission(audit_token, "modify_patient_records")
    print(f"Audit company has 'modify_patient_records' permission: {'Yes' if success else 'No'}")
    
    # Step 8: Query audit permissions
    print("\nStep 8: Checking query audit permissions")
    success, result = auth_manager.can_query_audit_records(audit_token)
    print(f"Audit company can query all audit records: {'Yes' if success else 'No'}")
    
    success, result = auth_manager.can_query_audit_records(session_token, "patient1")
    print(f"Patient can query their own audit records: {'Yes' if success else 'No'}")
    
    success, result = auth_manager.can_query_audit_records(session_token, "patient2")
    print(f"Patient can query another patient's audit records: {'Yes' if success else 'No'}")
    
    # Step 9: Logout
    print("\nStep 9: Logout")
    success, result = auth_manager.logout(session_token)
    print(f"Patient logout: {'Success' if success else 'Failed'} - {result}")
    
    # Try to use the token after logout (should fail)
    success, result = auth_manager.validate_session(session_token)
    print(f"Using token after logout: {'Valid' if success else 'Invalid'} - {result}")
    
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    demo_auth_flow()
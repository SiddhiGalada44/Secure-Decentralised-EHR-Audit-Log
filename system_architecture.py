"""
Secure Decentralized Audit System for EHR
Architecture Overview
"""
import json
import time
import hashlib
import uuid
import datetime
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# =============================================
# 1. User Authentication and Authorization
# =============================================

class User:
    def __init__(self, user_id, name, role):
        """
        Initialize user with role-based permissions
        
        Args:
            user_id: Unique identifier for user
            name: Name of the user
            role: Role of user (patient, doctor, admin, audit_company)
        """
        self.user_id = user_id
        self.name = name
        self.role = role
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def get_public_key_pem(self):
        """Return PEM encoded public key"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def sign_data(self, data):
        """Sign data with user's private key"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

class AuthenticationService:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        
    def register_user(self, user):
        """Register a user in the system"""
        self.users[user.user_id] = user
        return user
    
    def authenticate(self, user_id, signature, challenge):
        """Authenticate user based on signature of challenge"""
        if user_id not in self.users:
            return False, "User not found"
            
        user = self.users[user_id]
        
        try:
            # In a real implementation, verify the signature against the challenge
            # For simplicity, we're just checking if the user exists
            session_token = str(uuid.uuid4())
            self.sessions[session_token] = {
                "user_id": user_id,
                "expiry": datetime.datetime.now() + datetime.timedelta(hours=1)
            }
            return True, session_token
        except Exception as e:
            return False, str(e)
    
    def is_authorized(self, session_token, required_role=None, patient_id=None):
        """Check if session is valid and user has required permissions"""
        if session_token not in self.sessions:
            return False, "Invalid session"
            
        session = self.sessions[session_token]
        
        # Check session expiry
        if datetime.datetime.now() > session["expiry"]:
            del self.sessions[session_token]
            return False, "Session expired"
            
        user = self.users[session["user_id"]]
        
        # Check role-based permissions
        if required_role and user.role != required_role:
            # Special case: patients can access their own records
            if required_role == "patient" and user.role == "audit_company":
                return True, user
            elif user.role == "patient" and patient_id and user.user_id == patient_id:
                return True, user
            return False, "Insufficient permissions"
            
        return True, user

# =============================================
# 2. Audit Log Generator
# =============================================

class AuditLogGenerator:
    def __init__(self, auth_service):
        self.auth_service = auth_service
        
    def create_audit_record(self, session_token, patient_id, action_type, data=None):
        """
        Create an audit record when EHR data is accessed
        
        Args:
            session_token: Active session token
            patient_id: ID of the patient whose record was accessed
            action_type: Type of action (create, delete, change, query, print, copy)
            data: Additional data about the access (optional)
        """
        # Check authorization
        auth_result, user_or_msg = self.auth_service.is_authorized(session_token)
        if not auth_result:
            return False, user_or_msg
            
        user = user_or_msg
        
        # Create audit record
        timestamp = datetime.datetime.now().isoformat()
        record = {
            "record_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "patient_id": patient_id,
            "user_id": user.user_id,
            "user_role": user.role,
            "action_type": action_type,
            "data": data or {}
        }
        
        # Sign the record
        record["signature"] = user.sign_data(record)
        
        return True, record

# =============================================
# 3. Blockchain-based Audit Storage
# =============================================

class Block:
    def __init__(self, index, timestamp, records, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.records = records
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

        
    def calculate_hash(self):
        """Calculate SHA-256 hash of the block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "records": self.records,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()
        
    def mine_block(self, difficulty):
        """Mine block with proof of work"""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        print(f"Block #{self.index} mined: {self.hash}")
        return self.hash

class Blockchain:
    def __init__(self, difficulty=4):
        """Initialize blockchain with genesis block"""
        self.chain = []
        self.pending_records = []
        self.difficulty = difficulty
        self.nodes = set()  # For decentralization
        
        # Create genesis block
        self.create_genesis_block()
        
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = Block(0, datetime.datetime.now().isoformat(), [], "0")
        genesis_block.hash = genesis_block.calculate_hash()
        self.chain.append(genesis_block)
        
    def get_latest_block(self):
        """Return the latest block in the chain"""
        return self.chain[-1]
        
    def add_record(self, record):
        """Add audit record to pending records"""
        self.pending_records.append(record)
        return len(self.pending_records)
        
    def mine_pending_records(self, mining_reward_address):
        """Mine pending records into a new block"""
        if not self.pending_records:
            return False, "No pending records to mine"
            
        block = Block(
            len(self.chain),
            datetime.datetime.now().isoformat(),
            self.pending_records,
            self.get_latest_block().hash
        )
        
        block.mine_block(self.difficulty)
        self.chain.append(block)
        self.pending_records = []
        
        return True, block
        
    def is_chain_valid(self):
        """Validate the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Check if hash is correct
            if current_block.hash != current_block.calculate_hash():
                return False, "Current hash is invalid"
                
            # Check if this block points to the correct previous block
            if current_block.previous_hash != previous_block.hash:
                return False, "Previous hash is invalid"
                
        return True, "Blockchain is valid"
        
    def add_node(self, address):
        """Add a new node to the list of nodes"""
        self.nodes.add(address)
        return list(self.nodes)
        
    def replace_chain(self, new_chain):
        """
        Replace our chain with the longest valid chain in the network
        This is a key part of the consensus algorithm
        """
        if len(new_chain) <= len(self.chain):
            return False, "Received chain is not longer than current chain"
            
        # Check if the new chain is valid
        if not self.is_chain_valid(new_chain)[0]:
            return False, "Received chain is invalid"
            
        self.chain = new_chain
        return True, "Chain replaced successfully"
        
    def get_blocks_containing_patient_records(self, patient_id):
        """Retrieve blocks containing records for a specific patient"""
        patient_blocks = []
        
        for block in self.chain:
            patient_records = []
            for record in block.records:
                if record.get("patient_id") == patient_id:
                    patient_records.append(record)
                    
            if patient_records:
                block_copy = Block(
                    block.index, 
                    block.timestamp, 
                    patient_records, 
                    block.previous_hash
                )
                block_copy.hash = block.hash
                patient_blocks.append(block_copy)
                
        return patient_blocks

# =============================================
# 4. Query Interface
# =============================================

class QueryService:
    def __init__(self, auth_service, blockchain):
        self.auth_service = auth_service
        self.blockchain = blockchain
        
    def query_patient_records(self, session_token, patient_id):
        """
        Query audit records for a specific patient
        Patients can only query their own records
        Audit companies can query any patient's records
        """
        # Check authorization
        auth_result, user_or_msg = self.auth_service.is_authorized(
            session_token, 
            required_role=None,  # We'll handle the role check ourselves
            patient_id=patient_id
        )
        
        if not auth_result:
            return False, user_or_msg
            
        user = user_or_msg
        
        # Check if user is authorized to query this patient's records
        if user.role == "patient" and user.user_id != patient_id:
            return False, "Patients can only query their own records"
            
        # Get patient records from blockchain
        blocks = self.blockchain.get_blocks_containing_patient_records(patient_id)
        
        # Extract records from blocks
        records = []
        for block in blocks:
            for record in block.records:
                records.append(record)
                
        return True, records
        
    def query_all_records(self, session_token):
        """
        Query all audit records (only available to audit companies)
        """
        # Check authorization
        auth_result, user_or_msg = self.auth_service.is_authorized(
            session_token, 
            required_role="audit_company"
        )
        
        if not auth_result:
            return False, user_or_msg
            
        # Get all records from blockchain
        records = []
        for block in self.blockchain.chain:
            for record in block.records:
                records.append(record)
                
        return True, records

# =============================================
# 5. Tampering Detection
# =============================================

class TamperingDetector:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        
    def detect_tampering(self):
        """Detect if blockchain has been tampered with"""
        return self.blockchain.is_chain_valid()
        
    def simulate_tampering(self, block_index, record_index, field, new_value):
        """
        Simulate tampering with a record to demonstrate detection
        NOTE: In a real system, this would never exist - 
        it's only for demonstration purposes
        """
        if block_index >= len(self.blockchain.chain):
            return False, "Block index out of range"
            
        block = self.blockchain.chain[block_index]
        
        if record_index >= len(block.records):
            return False, "Record index out of range"
            
        # Make a copy of the original value for demonstration
        original_value = block.records[record_index].get(field)
        
        # Tamper with the record
        block.records[record_index][field] = new_value
        
        # Check if tampering is detected
        is_valid, message = self.blockchain.is_chain_valid()
        
        tampering_result = {
            "detected": not is_valid,
            "message": message,
            "tampered_block": block_index,
            "tampered_record": record_index,
            "tampered_field": field,
            "original_value": original_value,
            "new_value": new_value
        }
        
        return True, tampering_result

# =============================================
# 6. Data Privacy and Encryption
# =============================================

class PrivacyService:
    def __init__(self):
        pass
        
    def encrypt_sensitive_data(self, data, public_key_pem):
        """
        Encrypt sensitive data with the recipient's public key
        Uses hybrid encryption (symmetric key encrypted with public key)
        """
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        # Generate a random symmetric key
        symmetric_key = os.urandom(32)  # 256 bits
        iv = os.urandom(16)  # 128 bits
        
        # Encrypt data with symmetric key
        cipher = Cipher(
            algorithms.AES(symmetric_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padded_data = self._pad_data(data)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt symmetric key with recipient's public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return encrypted package
        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
    def _pad_data(self, data):
        """Pad data to AES block size (16 bytes)"""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length]) * padding_length
        return data + padding

# =============================================
# 7. EHR System Simulation
# =============================================

class EHRSystem:
    def __init__(self, auth_service, audit_log_generator, blockchain, query_service):
        self.auth_service = auth_service
        self.audit_log_generator = audit_log_generator
        self.blockchain = blockchain
        self.query_service = query_service
        
    def access_patient_record(self, session_token, patient_id, action_type):
        """Simulate accessing a patient record"""
        # Generate audit log
        result, audit_record = self.audit_log_generator.create_audit_record(
            session_token, patient_id, action_type
        )
        
        if not result:
            return False, audit_record  # Error message
            
        # Add audit record to blockchain
        self.blockchain.add_record(audit_record)
        
        # In a real system, we would mine blocks periodically or after a threshold
        # For demonstration, we mine after each access
        self.blockchain.mine_pending_records("system_reward_address")
        
        return True, f"Patient record accessed: {action_type}"
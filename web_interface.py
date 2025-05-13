from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import hashlib
import json
import os
import datetime
import uuid
import threading
import time
import sys

from auth_implementation import AuthManager

# ========== MOCK BLOCKCHAIN MANAGER ==========
class BlockchainManager:
    def __init__(self):
        self.records = []
        self.original_hashes = {}  # Store original hashes for integrity checking

    def add_record(self, record):
        # Add record index to the record
        record_index = len(self.records)
        record['record_index'] = record_index
        
        # Create hash of the original record for integrity verification
        record_hash = self.calculate_hash(record)
        self.original_hashes[record_index] = record_hash
        
        self.records.append(record)
        return record_index

    def calculate_hash(self, record):
        """Calculate a hash of the record for integrity checking"""
        # Create a consistent string representation of the record
        record_str = json.dumps(record, sort_keys=True)
        return hashlib.sha256(record_str.encode()).hexdigest()

    def get_patient_records(self, patient_id):
        return [r for r in self.records if r.get("patient_id") == patient_id]

    def get_all_records(self):
        return self.records

    def verify_blockchain(self):
        """Verify blockchain integrity by checking if records have been tampered with"""
        for i, record in enumerate(self.records):
            if i in self.original_hashes:
                current_hash = self.calculate_hash(record)
                original_hash = self.original_hashes[i]
                
                if current_hash != original_hash:
                    return False, f"Blockchain integrity compromised! Record {i} has been tampered with."
        
        return True, "Blockchain integrity verified: All records are valid"

    def tamper_with_record(self, record_index, field, new_value):
        if record_index >= len(self.records):
            return False, "Record index out of range"
        
        # Get the old value
        old_value = self.records[record_index].get(field)
        
        # Modify the record (this will break the hash verification)
        self.records[record_index][field] = new_value
        
        return True, {"old_value": old_value, "new_value": new_value}
# ==============================================

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize authentication manager and blockchain
auth_manager = AuthManager()
blockchain = BlockchainManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    user_id = request.form.get('user_id')
    name = request.form.get('name')
    role = request.form.get('role')
    email = request.form.get('email')

    success, result = auth_manager.register_user(user_id, name, role, email)
    if success:
        flash(f"User {name} registered successfully as {role}!", "success")
    else:
        flash(f"Registration failed: {result}", "danger")
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    user_id = request.form.get('user_id')

    # Step 1: generate challenge and store it
    success, result = auth_manager.login(user_id)
    if not success:
        flash(f"Login failed: {result}", "danger")
        return redirect(url_for('index'))

    challenge = result["challenge"]

    # Step 2: simulate signing the challenge using the user's private key
    private_key_pem = auth_manager.key_manager.get_user_private_key(user_id)
    if not private_key_pem:
        flash("User not registered or missing keys.", "danger")
        return redirect(url_for('index'))

    signature = auth_manager.key_manager.sign_data(challenge, private_key_pem)

    # Step 3: perform real login with challenge + signature
    success, result = auth_manager.login(user_id, challenge, signature)

    if success:
        session['user_id'] = result['user_id']
        session['role'] = result['role']
        session['session_token'] = result['session_token']
        user_info_success, user_info = auth_manager.get_user_info(result['session_token'])
        session['name'] = user_info["name"] if user_info_success else result['user_id']
        flash(f"Welcome back, {session['name']}!", "success")
    else:
        flash(f"Login failed: {result}", "danger")

    return redirect(url_for('index'))

    signature = auth_manager.key_manager.sign_data(challenge, private_key_pem)

    success, result = auth_manager.login(user_id, challenge, signature)

    if success:
        session['user_id'] = result['user_id']
        session['role'] = result['role']
        session['session_token'] = result['session_token']
        user_info_success, user_info = auth_manager.get_user_info(result['session_token'])
        session['name'] = user_info["name"] if user_info_success else result['user_id']
        flash(f"Welcome back, {session['name']}!", "success")
    else:
        flash(f"Login failed: {result}", "danger")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        session_token = session.get('session_token')
        auth_manager.logout(session_token)
        session.clear()
        flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/access_record', methods=['POST'])
def access_record():
    if 'user_id' not in session:
        flash("You must be logged in to access records.", "danger")
        return redirect(url_for('index'))

    patient_id = request.form.get('patient_id')
    action_type = request.form.get('action_type')
    session_token = session.get('session_token')

    success, result = auth_manager.access_patient_record(session_token, patient_id, action_type)
    if success:
        blockchain.add_record(result)
        flash(f"Successfully accessed record for patient {result['patient_id']}", "success")
    else:
        flash(f"Failed to access record: {result}", "danger")
    return redirect(url_for('index'))

@app.route('/query_audit', methods=['POST'])
def query_audit():
    if 'user_id' not in session:
        flash("You must be logged in to query audit records.", "danger")
        return redirect(url_for('index'))

    patient_id = request.form.get('patient_id')
    session_token = session.get('session_token')
    if session['role'] == 'patient':
        patient_id = session['user_id']

    can_query, _ = auth_manager.can_query_audit_records(session_token, patient_id)
    if not can_query:
        flash("You do not have permission to query these audit records.", "danger")
        return redirect(url_for('index'))

    records = blockchain.get_patient_records(patient_id) if patient_id else blockchain.get_all_records()
    return render_template('records.html', records=records, patient_id=patient_id)

@app.route('/verify_blockchain')
def verify_blockchain():
    if 'user_id' not in session or session['role'] != 'audit_company':
        flash("Only audit companies can verify the blockchain.", "danger")
        return redirect(url_for('index'))

    success, message = blockchain.verify_blockchain()
    flash(f"Blockchain verification: {message}", "success" if success else "danger")
    return redirect(url_for('index'))

@app.route('/simulate_tampering', methods=['POST'])
def simulate_tampering():
    if 'user_id' not in session or session['role'] != 'audit_company':
        flash("Only audit companies can simulate tampering.", "danger")
        return redirect(url_for('index'))

    record_index = int(request.form.get('record_index', 0))
    field = request.form.get('field')
    new_value = request.form.get('new_value')

    success, result = blockchain.tamper_with_record(record_index, field, new_value)
    if success:
        flash(f"Tampering simulation successful. Changed {field} to '{new_value}'", "warning")
        valid, message = blockchain.verify_blockchain()
        flash("Blockchain integrity: " + ("Passed (unexpected)" if valid else "Tampering detected"), "danger" if valid else "success")
    else:
        flash(f"Tampering simulation failed: {result}", "danger")
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True,use_reloader=False, use_debugger=False)
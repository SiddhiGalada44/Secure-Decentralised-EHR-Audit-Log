# Secure Decentralized Audit Logging System for Electronic Health Records (EHR)

This project implements a secure, decentralized audit logging system to ensure accountability and tamper-proof logging of Electronic Health Record (EHR) access. It integrates blockchain principles, cryptographic verification, and role-based access control to protect sensitive medical data in a distributed environment.

---

## Features

- **User Authentication & Role-Based Authorization**
  - Supports Admin, Doctor, Patient, and Audit Company roles.
  - JWT-based authentication integrated with secure key management.

- **EHR Access Simulation**
  - Users perform actions like viewing, modifying, or creating EHRs.
  - Each access generates a cryptographically signed audit log.

- **Audit Log Generation & Blockchain Logging**
  - Audit logs are appended to a Merkle Tree-based blockchain.
  - Blockchain blocks are validated with digital signatures and proof-of-work.

- **Tamper Detection**
  - Verifies blockchain integrity using Merkle root comparison and signature checks.
  - Alerts are raised for any unauthorized modification.

- **Web Interface (Flask)**
  - Login-based access with session tracking.
  - Users can view their audit logs and system integrity reports.

- **Distributed Node Support**
  - Simulates multi-node setup for decentralized logging and syncing.

---

## ️ System Architecture

1. **Authentication Layer**  
   - Built using `AuthenticationService`, `KeyManager`, and `UserStore`.

2. **Blockchain Layer**  
   - Implements Merkle Tree, Proof of Work, Block Signing, and Node Sync.

3. **Audit Log Generator**  
   - Creates structured JSON logs for each EHR event.

4. **Web Layer**  
   - Flask app for user interaction and dashboard access.

---

##  Demonstration Steps

1. Start multiple terminal windows to simulate different nodes:
   ```bash
   python blockchain_node.py --port 5001
   python blockchain_node.py --port 5002
   Launch Flask interface:
python web_interface.py
Log in as:
Admin → manage users and view full logs
Doctor → access/update patient records
Patient → view own records
Auditor → verify logs and blockchain integrity
Perform actions:
Create, modify, or access EHRs.
View how each action generates an immutable blockchain log.
Tamper a block (manually edit blockchain_data.pkl) and re-run verification to show failure.
Sync nodes and verify integrity across the distributed system.
## Cryptographic Components

Digital Signatures using RSA
Hashing with SHA-256
Merkle Trees for efficient record verification
Proof of Work to secure consensus
JWT Tokens for stateless session handling
## Assumptions & Limitations

Nodes simulated on a single machine; real deployment would use networked instances.
EHR actions are simulated and not connected to an actual medical database.
Proof of Work difficulty is reduced for demo purposes.
Blockchain syncing uses basic REST calls; can be extended with gRPC or pub-sub.
## File Structure

.
├── auth_implementation.py       # Authentication & authorization logic
├── blockchain_implementation.py # Merkle Tree, Blockchain, PoW
├── audit_log_generator.py       # Structured log generation
├── web_interface.py             # Flask web UI
├── blockchain_node.py           # Node simulation with sync support
├── static/, templates/          # Flask HTML & CSS
└── README.md
##
Tech Stack

Python 3.x
Flask
RSA Cryptography (via cryptography)
JSON, Pickle for storage
RESTful APIs for node communication



✨ Contributors

Siddhi Galada (MS CS, USC)




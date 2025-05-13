"""
Enhanced Blockchain Implementation for Decentralized Audit System

This module provides a more robust blockchain implementation specifically
designed for the decentralization requirement of the EHR audit system.
"""
import hashlib
import json
import time
import requests
import datetime
import threading
import pickle
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

class MerkleTree:
    """
    Merkle Tree implementation for efficient and secure verification
    of record integrity without needing the entire blockchain.
    """
    def __init__(self, records=None):
        self.records = records or []
        self.tree = self._build_tree()
        
    def _build_tree(self):
        """Build the Merkle tree from the records"""
        if not self.records:
            return [""]
            
        # Create leaf nodes by hashing records
        leaves = [self._hash(json.dumps(record, sort_keys=True)) for record in self.records]
        
        # If only one record, return it
        if len(leaves) == 1:
            return leaves
            
        # Build the tree
        tree = leaves.copy()
        while len(tree) > 1:
            # If odd number of nodes, duplicate the last one
            if len(tree) % 2 == 1:
                tree.append(tree[-1])
                
            # Create new level by combining pairs
            new_level = []
            for i in range(0, len(tree), 2):
                combined = tree[i] + tree[i+1]
                new_level.append(self._hash(combined))
                
            tree = new_level
            
        return tree
        
    def get_root(self):
        """Get the Merkle root (tree head)"""
        if not self.tree:
            return ""
        return self.tree[0]
        
    def get_proof(self, record_index):
        """
        Generate a Merkle proof for a specific record
        
        Args:
            record_index: Index of the record in the records list
            
        Returns:
            list: The Merkle proof as a list of hashes
        """
        if not self.records or record_index >= len(self.records):
            return []
            
        # Hash the target record
        record_hash = self._hash(json.dumps(self.records[record_index], sort_keys=True))
        
        # Generate proof
        proof = []
        index = record_index
        tree_size = len(self.records)
        tree_size = tree_size if tree_size % 2 == 0 else tree_size + 1
        
        while tree_size > 1:
            is_right = index % 2 == 1
            sibling_index = index - 1 if is_right else index + 1
            
            if sibling_index < len(self.records):
                sibling_hash = self._hash(json.dumps(self.records[sibling_index], sort_keys=True))
                proof.append((sibling_hash, is_right))
                
            # Move up the tree
            index = index // 2
            tree_size = tree_size // 2
            
        return proof
        
    def verify_proof(self, record, proof, root):
        """
        Verify a Merkle proof for a record
        
        Args:
            record: The record to verify
            proof: The Merkle proof
            root: The expected Merkle root
            
        Returns:
            bool: True if the proof is valid, False otherwise
        """
        if not proof:
            # If no proof provided, just check if record hash equals root
            record_hash = self._hash(json.dumps(record, sort_keys=True))
            return record_hash == root
            
        # Start with the record hash
        current = self._hash(json.dumps(record, sort_keys=True))
        
        # Apply each proof element
        for proof_hash, is_right in proof:
            if is_right:
                current = self._hash(current + proof_hash)
            else:
                current = self._hash(proof_hash + current)
                
        # Check if we reached the root
        return current == root
        
    def _hash(self, data):
        """Hash function for the Merkle tree"""
        if isinstance(data, str):
            data = data.encode()
            
        return hashlib.sha256(data).hexdigest()

class EnhancedBlock:
    """
    Enhanced block implementation with improved security features
    """
    def __init__(self, index, timestamp, records, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.records = records
        self.previous_hash = previous_hash
        self.merkle_tree = MerkleTree(records)
        self.merkle_root = self.merkle_tree.get_root()
        self.nonce = 0
        self.hash = self.calculate_hash()
        self.validator_signatures = {}  # For multi-node validation
        
    def calculate_hash(self):
        """Calculate SHA-256 hash of the block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
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
        
    def add_validator_signature(self, validator_id, signature):
        """Add a validator's signature to the block"""
        self.validator_signatures[validator_id] = signature
        return len(self.validator_signatures)
        
    def has_sufficient_validation(self, min_validators=2):
        """Check if block has enough validator signatures"""
        return len(self.validator_signatures) >= min_validators
        
    def verify_record(self, record_index):
        """
        Verify a specific record in the block without checking the entire chain
        Returns Merkle proof for the record
        """
        if record_index >= len(self.records):
            return False, "Record index out of range"
            
        record = self.records[record_index]
        proof = self.merkle_tree.get_proof(record_index)
        
        is_valid = self.merkle_tree.verify_proof(record, proof, self.merkle_root)
        
        return is_valid, proof if is_valid else "Invalid record"

class DecentralizedBlockchain:
    """
    Enhanced blockchain implementation with decentralization features
    """
    def __init__(self, node_id, difficulty=4):
        """
        Initialize blockchain
        
        Args:
            node_id: Unique identifier for this blockchain node
            difficulty: Mining difficulty
        """
        self.node_id = node_id
        self.chain = []
        self.pending_records = []
        self.difficulty = difficulty
        self.nodes = set()  # For decentralization
        
        # For consensus
        self.pending_blocks = {}  # Blocks waiting for validation
        
        # Create genesis block
        self.create_genesis_block()
        
        # Location for blockchain data persistence
        os.makedirs(f"blockchain_data_{node_id}", exist_ok=True)
        
        # Load chain if exists
        self._load_chain()
        
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = EnhancedBlock(0, datetime.datetime.now().isoformat(), [], "0")
        genesis_block.hash = genesis_block.calculate_hash()
        self.chain.append(genesis_block)
        
    def get_latest_block(self):
        """Return the latest block in the chain"""
        return self.chain[-1]
        
    def add_record(self, record):
        """Add audit record to pending records"""
        self.pending_records.append(record)
        
        # Save pending records
        self._save_pending_records()
        
        return len(self.pending_records)
        
    def mine_pending_records(self):
        """Mine pending records into a new block"""
        if not self.pending_records:
            return False, "No pending records to mine"
            
        block = EnhancedBlock(
            len(self.chain),
            datetime.datetime.now().isoformat(),
            self.pending_records,
            self.get_latest_block().hash
        )
        
        block.mine_block(self.difficulty)
        
        # Add to pending blocks waiting for validation
        block_id = block.hash
        self.pending_blocks[block_id] = {
            "block": block,
            "validators": {self.node_id: "self-validated"}
        }
        
        # Broadcast to other nodes for validation
        self._broadcast_block(block)
        
        # Clear pending records
        self.pending_records = []
        self._save_pending_records()
        
        return True, block_id
        
    def validate_block(self, block_data, validator_id, signature):
        """
        Validate a block received from another node
        
        Args:
            block_data: Serialized block data
            validator_id: ID of the validating node
            signature: Validator's signature
            
        Returns:
            bool: True if validation successful, False otherwise
        """
        try:
            # Deserialize block
            block = pickle.loads(block_data)
            
            # Verify block hash
            if block.hash != block.calculate_hash():
                return False, "Invalid block hash"
                
            # Verify block links to our chain
            if block.previous_hash != self.get_latest_block().hash:
                return False, "Block does not link to our chain"
                
            # Add validator signature
            block.add_validator_signature(validator_id, signature)
            
            # Store in pending blocks
            block_id = block.hash
            if block_id not in self.pending_blocks:
                self.pending_blocks[block_id] = {
                    "block": block,
                    "validators": {validator_id: signature}
                }
            else:
                self.pending_blocks[block_id]["validators"][validator_id] = signature
                
            # Check if block has enough validations
            if len(self.pending_blocks[block_id]["validators"]) >= 2:  # Require at least 2 validations
                # Add block to chain
                self.chain.append(block)
                
                # Remove from pending blocks
                del self.pending_blocks[block_id]
                
                # Save chain
                self._save_chain()
                
                return True, "Block added to chain"
                
            return True, "Block validation recorded"
            
        except Exception as e:
            return False, str(e)
            
    def is_chain_valid(self):
        """Validate the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Check if hash is correct
            if current_block.hash != current_block.calculate_hash():
                return False, f"Block {i} hash is invalid"
                
            # Check if this block points to the correct previous block
            if current_block.previous_hash != previous_block.hash:
                return False, f"Block {i} previous hash is invalid"
                
        return True, "Blockchain is valid"
        
    def add_node(self, address):
        """Add a new node to the list of nodes"""
        self.nodes.add(address)
        return list(self.nodes)
        
    def consensus(self):
        """
        Consensus algorithm to ensure all nodes have the same chain
        Implements a simplified version of practical Byzantine fault tolerance
        """
        replaced = False
        
        # Check each node for their chain
        for node in self.nodes:
            try:
                response = requests.get(f"{node}/chain")
                
                if response.status_code == 200:
                    node_chain = response.json()["chain"]
                    
                    # Deserialize chain from JSON
                    other_chain = []
                    for block_data in node_chain:
                        block = EnhancedBlock(
                            block_data["index"],
                            block_data["timestamp"],
                            block_data["records"],
                            block_data["previous_hash"]
                        )
                        block.hash = block_data["hash"]
                        block.merkle_root = block_data["merkle_root"]
                        other_chain.append(block)
                    
                    # Check if other chain is valid and longer
                    if len(other_chain) > len(self.chain):
                        is_valid, _ = self._is_chain_valid(other_chain)
                        
                        if is_valid:
                            self.chain = other_chain
                            replaced = True
            except:
                # Ignore nodes that aren't responding
                pass
                
        return replaced
        
    def _is_chain_valid(self, chain):
        """Check if a given chain is valid"""
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i-1]
            
            # Check if hash is correct
            if current_block.hash != current_block.calculate_hash():
                return False, f"Block {i} hash is invalid"
                
            # Check if this block points to the correct previous block
            if current_block.previous_hash != previous_block.hash:
                return False, f"Block {i} previous hash is invalid"
                
        return True, "Chain is valid"
        
    def get_patient_records(self, patient_id):
        """
        Retrieve all records for a specific patient across the blockchain
        Optimized to use Merkle proofs for verification
        """
        patient_records = []
        
        for block in self.chain:
            block_records = []
            
            for i, record in enumerate(block.records):
                if record.get("patient_id") == patient_id:
                    # Verify record with Merkle proof
                    is_valid, proof = block.verify_record(i)
                    
                    if is_valid:
                        record_copy = record.copy()
                        record_copy["block_index"] = block.index
                        record_copy["verified"] = is_valid
                        block_records.append(record_copy)
                    
            patient_records.extend(block_records)
            
        return patient_records
        
    def get_all_records(self):
        """Retrieve all records across the blockchain"""
        all_records = []
        
        for block in self.chain:
            for i, record in enumerate(block.records):
                record_copy = record.copy()
                record_copy["block_index"] = block.index
                
                # Verify record with Merkle proof
                is_valid, _ = block.verify_record(i)
                record_copy["verified"] = is_valid
                
                all_records.append(record_copy)
                
        return all_records
        
    def _broadcast_block(self, block):
        """Broadcast a new block to all nodes for validation"""
        # Serialize the block
        block_data = pickle.dumps(block)
        
        # Send to all nodes
        for node in self.nodes:
            try:
                requests.post(
                    f"{node}/validate_block",
                    data={
                        "block_data": block_data,
                        "validator_id": self.node_id,
                        "signature": "signature"  # In real implementation, this would be a digital signature
                    }
                )
            except:
                # Ignore nodes that aren't responding
                pass
                
    def _save_chain(self):
        """Save blockchain to disk"""
        try:
            with open(f"blockchain_data_{self.node_id}/chain.pkl", "wb") as f:
                pickle.dump(self.chain, f)
        except Exception as e:
            print(f"Error saving blockchain: {e}")
            
    def _load_chain(self):
        """Load blockchain from disk"""
        try:
            if os.path.exists(f"blockchain_data_{self.node_id}/chain.pkl"):
                with open(f"blockchain_data_{self.node_id}/chain.pkl", "rb") as f:
                    self.chain = pickle.load(f)
                print(f"Loaded blockchain with {len(self.chain)} blocks")
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            print("Starting with fresh blockchain")
            
    def _save_pending_records(self):
        """Save pending records to disk"""
        try:
            with open(f"blockchain_data_{self.node_id}/pending_records.pkl", "wb") as f:
                pickle.dump(self.pending_records, f)
        except Exception as e:
            print(f"Error saving pending records: {e}")
            
    def _load_pending_records(self):
        """Load pending records from disk"""
        try:
            if os.path.exists(f"blockchain_data_{self.node_id}/pending_records.pkl"):
                with open(f"blockchain_data_{self.node_id}/pending_records.pkl", "rb") as f:
                    self.pending_records = pickle.load(f)
                print(f"Loaded {len(self.pending_records)} pending records")
        except Exception as e:
            print(f"Error loading pending records: {e}")


# Node Server Implementation for Distributed Blockchain Network
class BlockchainNode:
    """
    Implementation of a blockchain node for the decentralized audit system
    This would typically run as a separate service on different machines
    """
    def __init__(self, node_id, host="localhost", port=5000):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.blockchain = DecentralizedBlockchain(node_id)
        
        # In a real implementation, this would use a web framework like Flask
        # For this demonstration, we'll simulate the endpoints
        
    def start(self):
        """Start the blockchain node server"""
        print(f"Blockchain Node {self.node_id} started at {self.host}:{self.port}")
        print(f"Blockchain has {len(self.blockchain.chain)} blocks")
        
        # In a real implementation, this would start a web server
        # For this demonstration, we'll simulate endpoints through function calls
        
    def register_node(self, node_address):
        """Register a new node in the network"""
        self.blockchain.add_node(node_address)
        return {"message": f"Node {node_address} added", "total_nodes": list(self.blockchain.nodes)}
        
    def get_chain(self):
        """Return the full blockchain"""
        chain_data = []
        
        for block in self.blockchain.chain:
            block_data = {
                "index": block.index,
                "timestamp": block.timestamp,
                "records": block.records,
                "merkle_root": block.merkle_root,
                "previous_hash": block.previous_hash,
                "hash": block.hash
            }
            chain_data.append(block_data)
            
        return {
            "chain": chain_data,
            "length": len(chain_data)
        }
        
    def validate_block(self, block_data, validator_id, signature):
        """Validate a block from another node"""
        success, message = self.blockchain.validate_block(block_data, validator_id, signature)
        
        return {
            "success": success,
            "message": message
        }
        
    def mine_block(self):
        """Mine pending records into a new block"""
        success, result = self.blockchain.mine_pending_records()
        
        if success:
            return {
                "message": "New block mined",
                "block_id": result
            }
        else:
            return {
                "message": "Mining failed",
                "error": result
            }
            
    def consensus(self):
        """Run consensus algorithm to sync with the network"""
        replaced = self.blockchain.consensus()
        
        if replaced:
            return {
                "message": "Chain was replaced",
                "new_chain": self.get_chain()
            }
        else:
            return {
                "message": "Chain is authoritative",
                "chain": self.get_chain()
            }
            
    def add_record(self, record):
        """Add a new audit record to the blockchain"""
        index = self.blockchain.add_record(record)
        
        return {
            "message": "Record added to pending records",
            "total_pending": index
        }
        
    def get_patient_records(self, patient_id):
        """Get all records for a specific patient"""
        records = self.blockchain.get_patient_records(patient_id)
        
        return {
            "patient_id": patient_id,
            "records": records,
            "count": len(records)
        }
        
    def get_all_records(self):
        """Get all records from the blockchain"""
        records = self.blockchain.get_all_records()
        
        return {
            "records": records,
            "count": len(records)
        }

# Demonstration of a multi-node network setup
def setup_blockchain_network(num_nodes=3):
    """Set up a network of blockchain nodes for demonstration"""
    nodes = []
    
    # Create nodes
    for i in range(1, num_nodes + 1):
        node = BlockchainNode(f"node{i}", port=5000 + i)
        nodes.append(node)
        
    # Register nodes with each other (create a fully connected network)
    for i, node in enumerate(nodes):
        for j, other_node in enumerate(nodes):
            if i != j:
                node.register_node(f"http://localhost:{5000 + j + 1}")
                
    # Start all nodes
    for node in nodes:
        node.start()
        
    return nodes
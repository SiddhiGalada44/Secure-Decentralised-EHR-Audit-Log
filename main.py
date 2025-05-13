"""
Main script for the Secure Decentralized Audit System
Integrates all components and provides a command-line interface
"""
import argparse
import os
import sys
import time
import threading
import json
import signal
import subprocess
import webbrowser

# Import project components 
# In a real implementation, these would be in separate modules
# You would need to make sure all files are in the same directory
# or properly installed as packages

# Function to start the web server
def start_web_server(host="0.0.0.0", port=5000):
    """Start the web server"""
    print(f"Starting web server at http://{host}:{port}/")
    
    try:
        # Import the web server module
        from web_interface import run_web_server
        # Run the web server
        run_web_server(host=host, port=port)
    except ImportError:
        print("Web interface module not found. Starting web server in a separate process...")
        subprocess.Popen([sys.executable, "web_interface.py"])

# Function to start blockchain nodes
def start_blockchain_nodes(num_nodes=3):
    """Start blockchain nodes"""
    print(f"Starting {num_nodes} blockchain nodes...")
    
    try:
        # Import the blockchain implementation
        from blockchain_implementation import setup_blockchain_network
        # Set up the blockchain network
        nodes = setup_blockchain_network(num_nodes)
        return nodes
    except ImportError:
        print("Blockchain implementation module not found.")
        return None

# Function to demonstrate basic functionality
def run_demo():
    """Run a demonstration of the system"""
    print("\n=== SECURE DECENTRALIZED AUDIT SYSTEM DEMO ===\n")
    
    # Try to import and run the auth demo
    try:
        from auth_implementation import demo_auth_flow
        print("Running authentication and authorization demo...")
        demo_auth_flow()
    except ImportError:
        print("Auth implementation module not found. Skipping auth demo.")
    
    # Try to import and run the demo script
    try:
        import demonstration_script
        print("\nRunning full system demonstration...")
        demonstration_script.run_demo()
    except ImportError:
        print("Demonstration script not found. Skipping system demo.")
    
    print("\nDemo completed.")

# Function to print system info
def print_system_info():
    """Print information about the system"""
    print("\n=== SYSTEM INFORMATION ===\n")
    
    # Check for available components
    components = {
        "Authentication System": os.path.exists("auth_implementation.py"),
        "Blockchain Implementation": os.path.exists("blockchain_implementation.py"),
        "Web Interface": os.path.exists("web_interface.py"),
        "Client/Server Stubs": os.path.exists("client_server_stubs.py"),
        "Demonstration Script": os.path.exists("demonstration_script.py")
    }
    
    # Print component status
    print("Available Components:")
    for component, available in components.items():
        print(f"  {component}: {'✓' if available else '✗'}")
    
    # Print additional info
    print("\nSystem Structure:")
    print("  1. Authentication and Authorization")
    print("     - Role-based access control (RBAC)")
    print("     - Public key infrastructure (PKI)")
    print("     - JSON Web Token (JWT) sessions")
    print("\n  2. Blockchain-based Audit Storage")
    print("     - Decentralized immutable ledger")
    print("     - Merkle tree verification")
    print("     - Tamper detection")
    print("\n  3. Web Interface")
    print("     - User-friendly dashboard")
    print("     - RESTful API endpoints")
    print("     - Real-time blockchain verification")
    
    print("\nDesign Highlights:")
    print("  - Privacy: Sensitive data is encrypted and access-controlled")
    print("  - Authentication: Strong PKI-based user authentication")
    print("  - Authorization: Fine-grained permission system")
    print("  - Immutability: Blockchain ensures tamper-evident audit logs")
    print("  - Decentralization: No single point of trust or failure")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Secure Decentralized Audit System")
    parser.add_argument("--mode", choices=["web", "demo", "info"], default="info",
                      help="Run mode: web server, demo, or info")
    parser.add_argument("--host", default="127.0.0.1", help="Web server host")
    parser.add_argument("--port", type=int, default=5000, help="Web server port")
    parser.add_argument("--nodes", type=int, default=3, help="Number of blockchain nodes")
    parser.add_argument("--open-browser", action="store_true", help="Open web browser")
    
    args = parser.parse_args()
    
    if args.mode == "web":
        # Start blockchain nodes
        nodes = start_blockchain_nodes(args.nodes)
        
        # Start web server
        if args.open_browser:
            # Open browser after a short delay
            threading.Timer(
                1.5, 
                lambda: webbrowser.open(f"http://{args.host}:{args.port}/")
            ).start()
            
        start_web_server(args.host, args.port)
        
    elif args.mode == "demo":
        run_demo()
        
    elif args.mode == "info":
        print_system_info()

if __name__ == "__main__":
    # Handle keyboard interrupt gracefully
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
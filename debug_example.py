#!/usr/bin/env python3

import os
import time
import sys

def main():
    print("Starting debug example...")
    
    # File operations
    with open("/tmp/test_file.txt", "w") as f:
        f.write("Hello from Python!\n")
    
    # Read the file back
    with open("/tmp/test_file.txt", "r") as f:
        content = f.read()
        print(f"Read: {content.strip()}")
    
    # Network operation (will show socket syscalls)
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        print("Network connection successful")
    except Exception as e:
        print(f"Network error: {e}")
    
    # Process information
    print(f"PID: {os.getpid()}")
    print(f"Current working directory: {os.getcwd()}")
    
    # Sleep to show time-related syscalls
    print("Sleeping for 2 seconds...")
    time.sleep(2)
    
    # Clean up
    os.remove("/tmp/test_file.txt")
    print("Debug example completed")

if __name__ == "__main__":
    main()
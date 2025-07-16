#!/usr/bin/env python3

import os
import sys
import time

def buggy_file_operations():
    print("Attempting file operations...")
    
    # This will fail - trying to write to a directory that doesn't exist
    try:
        with open("/nonexistent/dir/file.txt", "w") as f:
            f.write("This should fail")
    except Exception as e:
        print(f"File error: {e}")
    
    # This will fail - permission denied
    try:
        with open("/etc/passwd", "w") as f:
            f.write("hacker attempt")
    except Exception as e:
        print(f"Permission error: {e}")

def buggy_network():
    print("Attempting network operations...")
    
    # This will fail - invalid address
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("999.999.999.999", 12345))
        sock.close()
    except Exception as e:
        print(f"Network error: {e}")

def memory_issue():
    print("Creating memory pressure...")
    
    # Allocate large chunks of memory
    data = []
    for i in range(1000):
        data.append("X" * 1024 * 1024)  # 1MB chunks
        if i % 100 == 0:
            print(f"Allocated {i} MB")
            time.sleep(0.1)

def infinite_loop():
    print("Starting infinite loop (Ctrl+C to stop)...")
    counter = 0
    while True:
        counter += 1
        if counter % 1000000 == 0:
            print(f"Loop iteration: {counter}")
        time.sleep(0.001)

def main():
    print(f"PID: {os.getpid()}")
    print("Choose a bug to debug:")
    print("1. File operation errors")
    print("2. Network errors") 
    print("3. Memory allocation")
    print("4. Infinite loop")
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice == "1":
        buggy_file_operations()
    elif choice == "2":
        buggy_network()
    elif choice == "3":
        memory_issue()
    elif choice == "4":
        infinite_loop()
    else:
        print("Invalid choice, running file operations by default")
        buggy_file_operations()

if __name__ == "__main__":
    main()
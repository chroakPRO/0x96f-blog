---
layout: single
title: "ptrace System Call Hooking in Python - Building a File Access Monitor"
date: 2025-07-15
categories: [linux, security, system-monitoring]
tags: [ptrace, python, syscalls, file-monitoring, security-tools]
toc: true
toc_label: "Contents"
toc_icon: "cog"
excerpt: "Learn to build a Python-based file access monitoring tool using ptrace to intercept and analyze system calls for security monitoring and process behavior analysis."
---

## Overview
**Target Audience:** Security researchers, system administrators, Python developers  
**Reading Time:** 15-20 minutes  
**Difficulty Level:** Intermediate to Advanced  
**What You'll Learn:**
- Building ptrace-based monitoring tools in Python
- Intercepting file-related system calls (open, read, write, close)
- Process behavior analysis and security monitoring
- Python ctypes integration with low-level system interfaces
- Real-time file access auditing techniques

**Prerequisites:** 
- Strong Python programming knowledge
- Basic understanding of Linux system calls
- Familiarity with process management concepts
- Command line experience

## Introduction

### The Need for File Access Monitoring

In today's security landscape, understanding what files a process accesses is crucial for:
- Security incident response and forensics
- Malware behavior analysis  
- Compliance monitoring and audit trails
- Detecting unauthorized file access
- Understanding application behavior

### Why ptrace + Python?

While traditional tools like `strace` provide basic system call tracing, building a custom solution offers:
- **Programmatic control** - Filter and process events in real-time
- **Enhanced logging** - Rich metadata and context
- **Integration capabilities** - Easy connection to larger security frameworks
- **Customization** - Tailor monitoring to specific needs

### What We'll Build

We'll construct a complete file access monitoring system that can:
- Attach to any running process
- Monitor file operations (open, read, write, close)
- Provide detailed metadata including permissions, ownership, and timestamps
- Display real-time file access events with context

## Problem Statement

### The Challenge

System administrators and security teams need visibility into file access patterns but face limitations:

- **Black box processes** - No insight into what files applications access
- **Performance overhead** - Traditional monitoring tools can be resource-intensive
- **Limited context** - Basic tools show operations but lack rich metadata
- **Integration gaps** - Difficulty connecting monitoring to security workflows

### Our Solution Approach

We'll build a Python-based monitoring tool that leverages ptrace to provide:
- Real-time file access monitoring with minimal overhead
- Rich metadata including file permissions, ownership, and timestamps
- Flexible filtering and customization options
- Clean, readable output suitable for analysis

## Core Concepts

### Concept 1: Python ctypes and ptrace Integration

**Definition:** Using Python's ctypes library to interface directly with the ptrace system call, enabling low-level process control from high-level Python code.

**Why It Matters:** This combination provides the power of C-level system programming with Python's ease of use and rapid development capabilities.

**Key Components:**
- **ctypes.CDLL** - Interface to libc for ptrace calls
- **Structure classes** - Represent C structures in Python
- **Register access** - Reading CPU registers to extract syscall information

### Concept 2: File System Call Interception

**Definition:** Monitoring specific system calls related to file operations to track process file access behavior.

**Target System Calls:**
- **open/openat** - File opening operations
- **read** - Reading data from files
- **write** - Writing data to files  
- **close** - Closing file descriptors

### Concept 3: Process Context and Metadata

**Definition:** Enriching basic system call information with process details and file metadata to provide comprehensive monitoring context.

**Enhanced Information:**
- Process name, user, and command line
- File permissions, ownership, and timestamps
- File descriptor to path mapping
- Socket information for network connections

## Step-by-Step Implementation

### Phase 1: Core Infrastructure

#### Step 1: Main Entry Point (`main.py`)

```python
#!/usr/bin/env python3
import sys
import signal
from tracer import ProcessTracer
from utils import validate_pid, get_process_info

def signal_handler(signum, frame):
    print("\n[INFO] Shutting down...")
    sys.exit(0)

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <PID>")
        sys.exit(1)
    
    try:
        pid = int(sys.argv[1])
    except ValueError:
        print("Error: PID must be a number")
        sys.exit(1)
    
    if not validate_pid(pid):
        print(f"Error: Process {pid} not found or not accessible")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    process_name = get_process_info(pid)
    print(f"[INFO] Monitoring file access for PID {pid} ({process_name})")
    print("[INFO] Press Ctrl+C to stop")
    print("-" * 50)
    
    tracer = ProcessTracer(pid)
    try:
        tracer.attach()
        tracer.monitor_syscalls()
    except PermissionError:
        print("Error: Permission denied. Try running with sudo.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
```

**Explanation:** This entry point handles command-line arguments, validates the target PID, and initializes the monitoring system with proper error handling.

#### Step 2: System Call Definitions (`syscalls.py`)

```python
# x86_64 syscall numbers for file operations
FILE_SYSCALLS = {
    0: 'read',
    1: 'write', 
    2: 'open',
    3: 'close',
    257: 'openat',
}

# Syscall argument positions (x86_64 calling convention)
SYSCALL_ARGS = {
    'open': ['filename', 'flags', 'mode'],      # rdi, rsi, rdx
    'openat': ['dirfd', 'filename', 'flags', 'mode'],  # rdi, rsi, rdx, r10
    'read': ['fd', 'buffer', 'count'],          # rdi, rsi, rdx
    'write': ['fd', 'buffer', 'count'],         # rdi, rsi, rdx
    'close': ['fd'],                            # rdi
}

def is_file_syscall(syscall_num):
    """Check if syscall is file-related"""
    return syscall_num in FILE_SYSCALLS

def get_syscall_name(syscall_num):
    """Get syscall name from number"""
    return FILE_SYSCALLS.get(syscall_num, f"syscall_{syscall_num}")
```

### Phase 2: Process Tracing Implementation

#### Step 3: Core Tracer Class (`tracer.py`)

```python
import os
import sys
import ctypes
import signal
from ctypes import c_long, c_int, c_void_p, Structure
from syscalls import is_file_syscall, get_syscall_name
from utils import format_flags, fd_to_path, get_process_info
import time

# ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12

class user_regs_struct(Structure):
    """x86_64 register structure for accessing syscall arguments"""
    _fields_ = [
        ("r15", c_long), ("r14", c_long), ("r13", c_long), ("r12", c_long),
        ("rbp", c_long), ("rbx", c_long), ("r11", c_long), ("r10", c_long),
        ("r9", c_long), ("r8", c_long), ("rax", c_long), ("rcx", c_long),
        ("rdx", c_long), ("rsi", c_long), ("rdi", c_long), ("orig_rax", c_long),
        ("rip", c_long), ("cs", c_long), ("eflags", c_long), ("rsp", c_long),
        ("ss", c_long), ("fs_base", c_long), ("gs_base", c_long),
        ("ds", c_long), ("es", c_long), ("fs", c_long), ("gs", c_long),
    ]

class ProcessTracer:
    def __init__(self, pid):
        self.pid = pid
        self.libc = ctypes.CDLL("libc.so.6")
        self.attached = False
        self.process_info = get_process_info(pid)
        
        if self.process_info:
            print(f"[INFO] Process details:")
            print(f"  Name: {self.process_info['name']}")
            print(f"  User: {self.process_info['user']}")
            print(f"  Command: {self.process_info['cmdline']}")
            print(f"  Working Dir: {self.process_info['cwd']}")
            print(f"  Started: {self.process_info['start_time']}")
            print("-" * 50)
        
    def attach(self):
        """Attach to target process using ptrace"""
        result = self.libc.ptrace(PTRACE_ATTACH, self.pid, 0, 0)
        if result == -1:
            raise Exception(f"Failed to attach to PID {self.pid}")
        os.waitpid(self.pid, 0)
        self.attached = True
        print(f"[INFO] Attached to process {self.pid}")
        
    def detach(self):
        """Detach from process cleanly"""
        if self.attached:
            self.libc.ptrace(PTRACE_DETACH, self.pid, 0, 0)
            self.attached = False
            print(f"[INFO] Detached from process {self.pid}")
```

#### Step 4: Memory Reading and Syscall Parsing

```python
    def read_string(self, address, max_len=256):
        """Read null-terminated string from process memory"""
        if address == 0:
            return None
        result = ""
        for i in range(0, max_len, 8):
            try:
                data = self.libc.ptrace(1, self.pid, address + i, 0)  # PTRACE_PEEKDATA
                if data == -1:
                    break
                bytes_data = data.to_bytes(8, 'little')
                for byte in bytes_data:
                    if byte == 0:
                        return result
                    result += chr(byte)
            except:
                break
        return result

    def parse_syscall_args(self, regs, syscall_name):
        """Extract syscall arguments based on x86_64 calling convention"""
        args = {}
        if syscall_name == 'open':
            args['filename'] = self.read_string(regs.rdi)
            args['flags'] = regs.rsi
            args['mode'] = regs.rdx
        elif syscall_name == 'openat':
            args['dirfd'] = regs.rdi
            args['filename'] = self.read_string(regs.rsi)
            args['flags'] = regs.rdx
            args['mode'] = regs.r10
        elif syscall_name in ['read', 'write']:
            args['fd'] = regs.rdi
            args['count'] = regs.rdx
        elif syscall_name == 'close':
            args['fd'] = regs.rdi
        return args
```

### Phase 3: Enhanced Logging and Monitoring

#### Step 5: Rich File Access Logging

```python
    def log_file_access(self, timestamp, syscall_name, args):
        """Enhanced log file access event with detailed information"""
        proc_name = self.process_info['name'] if self.process_info else 'unknown'
        proc_user = self.process_info['user'] if self.process_info else 'unknown'
        
        if syscall_name in ['open', 'openat']:
            filename = args.get('filename', 'unknown')
            flags = format_flags(args.get('flags', 0))
            mode = oct(args.get('mode', 0))[-4:]
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] OPEN: {filename}")
            print(f"  Flags: {flags}")
            print(f"  Mode: {mode}")
            
        elif syscall_name == 'read':
            fd = args.get('fd', -1)
            count = args.get('count', 0)
            path = fd_to_path(self.pid, fd)
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] READ: {path}")
            print(f"  Bytes requested: {count}")
            
        elif syscall_name == 'write':
            fd = args.get('fd', -1)
            count = args.get('count', 0)
            path = fd_to_path(self.pid, fd)
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] WRITE: {path}")
            print(f"  Bytes written: {count}")
            
        elif syscall_name == 'close':
            fd = args.get('fd', -1)
            path = fd_to_path(self.pid, fd)
            print(f"[{timestamp}] {proc_name}({self.pid})[{proc_user}] CLOSE: {path}")

    def monitor_syscalls(self):
        """Main monitoring loop with enhanced file syscall handling"""
        try:
            while True:
                self.continue_syscall()
                regs = self.get_registers()
                if regs:
                    self.handle_syscall(regs)
                self.continue_syscall()
        except KeyboardInterrupt:
            print("\n[INFO] Monitoring stopped")
        except ProcessLookupError:
            print(f"[INFO] Process {self.pid} terminated")
        finally:
            self.detach()
```

#### Step 6: Utility Functions (`utils.py`)

```python
import os
import pwd
import grp
import psutil
from datetime import datetime

def get_process_info(pid):
    """Get comprehensive process information"""
    try:
        proc = psutil.Process(pid)
        return {
            'name': proc.name(),
            'user': proc.username(),
            'cmdline': ' '.join(proc.cmdline()),
            'cwd': proc.cwd(),
            'start_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
    except:
        return None

def fd_to_path(pid, fd):
    """Enhanced fd to path resolution with metadata"""
    try:
        path = os.readlink(f'/proc/{pid}/fd/{fd}')
        
        # Handle different types of file descriptors
        if path.startswith('socket:['):
            inode = path.split('[')[1].rstrip(']')
            return get_socket_info(pid, inode)
        elif os.path.exists(path):
            metadata = get_file_metadata(path)
            return f"{path} ({metadata})" if metadata else path
        else:
            return path
    except Exception as e:
        return f'fd={fd}'

def format_flags(flags):
    """Convert open flags to readable format"""
    flag_names = []
    if flags & 0o0:     flag_names.append('O_RDONLY')
    if flags & 0o1:     flag_names.append('O_WRONLY') 
    if flags & 0o2:     flag_names.append('O_RDWR')
    if flags & 0o100:   flag_names.append('O_CREAT')
    if flags & 0o1000:  flag_names.append('O_TRUNC')
    if flags & 0o2000:  flag_names.append('O_APPEND')
    if flags & 0o4000:  flag_names.append('O_NONBLOCK')
    if flags & 0o200000: flag_names.append('O_CLOEXEC')
    return '|'.join(flag_names) if flag_names else f'0x{flags:x}'
```

## Real-World Examples

### Example 1: Security Monitoring

**Scenario:** Monitoring a web server process for suspicious file access patterns.

```bash
# Monitor nginx process
sudo python3 main.py $(pgrep nginx | head -1)

# Example output:
[INFO] Monitoring file access for PID 1234 (nginx)
[INFO] Process details:
  Name: nginx
  User: www-data
  Command: nginx: worker process
  Working Dir: /
  Started: 2025-07-15 10:30:15
--------------------------------------------------
[10:45:23] nginx(1234)[www-data] OPEN: /var/log/nginx/access.log
  Flags: O_WRONLY|O_APPEND
  Mode: 0644
[10:45:23] nginx(1234)[www-data] WRITE: /var/log/nginx/access.log (owner=www-data:adm mode=0644 size=1024 mtime=2025-07-15 10:45:23)
  Bytes written: 127
```

### Example 2: Application Behavior Analysis

**Scenario:** Understanding what configuration files an application reads during startup.

```bash
# Start monitoring before application launch
sudo python3 main.py $(pgrep myapp)

# Output shows configuration file access:
[10:50:15] myapp(5678)[user] OPEN: /etc/myapp/config.yaml
  Flags: O_RDONLY
  Mode: 0000
[10:50:15] myapp(5678)[user] READ: /etc/myapp/config.yaml (owner=root:root mode=0644 size=2048 mtime=2025-07-15 09:30:00)
  Bytes requested: 2048
```

## Performance Considerations

### Overhead Analysis

Our Python implementation introduces overhead through:
- **Python interpreter** - Additional processing layer
- **ctypes calls** - Function call overhead for each ptrace operation
- **String processing** - Memory reading and parsing

### Optimization Strategies

1. **Selective Monitoring** - Only trace file-related syscalls
2. **Efficient Memory Reading** - Read memory in chunks
3. **Lazy Evaluation** - Only resolve paths when needed

```python
# Example optimization: Cache file descriptor mappings
class ProcessTracer:
    def __init__(self, pid):
        # ... existing code ...
        self.fd_cache = {}  # Cache fd to path mappings
        
    def fd_to_path_cached(self, fd):
        if fd not in self.fd_cache:
            self.fd_cache[fd] = fd_to_path(self.pid, fd)
        return self.fd_cache[fd]
```

## Common Pitfalls & Solutions

### Pitfall 1: Permission Errors

**Description:** Insufficient privileges to attach to target processes.

**Symptoms:** 
- "Permission denied" errors
- Failed ptrace attachment

**Solution:**
```bash
# Run with sudo
sudo python3 main.py <PID>

# Or add capabilities (for production deployment)
sudo setcap cap_sys_ptrace+ep /usr/bin/python3
```

### Pitfall 2: Process State Confusion

**Description:** Target process in uninterruptible state or zombie state.

**Solution:**
```python
def validate_pid(pid):
    """Enhanced PID validation with state checking"""
    try:
        proc = psutil.Process(pid)
        if proc.status() in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]:
            return False
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
```

## Best Practices

### Security Considerations

1. **Principle of Least Privilege** - Only request necessary permissions
2. **Input Validation** - Validate all PID inputs
3. **Error Handling** - Graceful handling of edge cases
4. **Logging** - Audit trail of monitoring activities

### Code Organization

1. **Modular Design** - Separate concerns into different modules
2. **Configuration** - Make syscall sets configurable
3. **Testing** - Unit tests for utility functions
4. **Documentation** - Clear inline documentation

## Usage Examples

### Basic File Monitoring

```bash
# Monitor a specific process
python3 main.py 1234

# Monitor process by name
python3 main.py $(pgrep firefox)

# Monitor with elevated privileges
sudo python3 main.py 1234
```

### Advanced Use Cases

```bash
# Monitor and log to file
python3 main.py 1234 | tee file_access.log

# Filter specific file types
python3 main.py 1234 | grep '\.conf\|\.yaml\|\.json'

# Monitor multiple processes (requires process spawning)
for pid in $(pgrep nginx); do
    python3 main.py $pid &
done
```

## Conclusion

### Key Takeaways

1. **Python + ptrace = Powerful Monitoring** - Combining Python's ease with ptrace's capabilities creates effective monitoring tools
2. **Rich Context Matters** - File metadata and process information provide valuable security insights
3. **Modular Design Enables Flexibility** - Well-structured code allows easy customization and extension
4. **Real-time Monitoring Has Security Value** - Live file access tracking enables rapid incident response

### Next Steps

1. **Extend to Network Monitoring** - Add socket syscall monitoring
2. **Add Filtering Capabilities** - Implement configurable filtering rules
3. **Create Output Formats** - JSON, CSV, or database integration
4. **Build Alert System** - Trigger alerts on suspicious patterns

## Additional Resources

### Python Security Libraries
- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process utilities
- [python-ptrace](https://github.com/vstinner/python-ptrace) - Pure Python ptrace library

### System Programming
- [Linux Programming Interface](http://man7.org/tlpi/) - Comprehensive system programming guide
- [ptrace(2) Manual](https://man7.org/linux/man-pages/man2/ptrace.2.html) - Official ptrace documentation
- [System Call Table](https://syscalls.mebeim.net/?table=x86/64/x64/v6.2) - x86_64 syscall reference
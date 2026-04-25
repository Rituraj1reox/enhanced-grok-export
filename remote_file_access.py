"""
Remote File Access Module
Provides secure methods to access, read, write, and manage files on remote servers.
Supports SSH, SFTP, and HTTP/HTTPS protocols.
"""

import os
import paramiko
import requests
from pathlib import Path
from typing import Union, Optional, List
from io import BytesIO
import json


class RemoteFileAccess:
    """Base class for remote file operations"""
    
    def __init__(self):
        self.connected = False
    
    def connect(self):
        raise NotImplementedError
    
    def disconnect(self):
        raise NotImplementedError
    
    def read_file(self, file_path: str) -> str:
        raise NotImplementedError
    
    def write_file(self, file_path: str, content: str) -> bool:
        raise NotImplementedError
    
    def list_files(self, directory: str) -> List[str]:
        raise NotImplementedError
    
    def delete_file(self, file_path: str) -> bool:
        raise NotImplementedError


class SFTPFileAccess(RemoteFileAccess):
    """SFTP (SSH File Transfer Protocol) for secure remote file access"""
    
    def __init__(self, host: str, username: str, password: Optional[str] = None, 
                 private_key_path: Optional[str] = None, port: int = 22):
        """
        Initialize SFTP connection parameters
        
        Args:
            host: Remote server hostname/IP
            username: SSH username
            password: SSH password (if using password auth)
            private_key_path: Path to private key file (if using key auth)
            port: SSH port (default: 22)
        """
        super().__init__()
        self.host = host
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.port = port
        self.ssh_client = None
        self.sftp_client = None
    
    def connect(self) -> bool:
        """Establish SFTP connection"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using private key if provided
            if self.private_key_path:
                private_key = paramiko.RSAKey.from_private_key_file(self.private_key_path)
                self.ssh_client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=private_key
                )
            else:
                # Connect using password
                self.ssh_client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password
                )
            
            self.sftp_client = self.ssh_client.open_sftp()
            self.connected = True
            print(f"✓ Connected to {self.host} via SFTP")
            return True
        
        except Exception as e:
            print(f"✗ SFTP Connection failed: {str(e)}")
            return False
    
    def disconnect(self) -> bool:
        """Close SFTP connection"""
        try:
            if self.sftp_client:
                self.sftp_client.close()
            if self.ssh_client:
                self.ssh_client.close()
            self.connected = False
            print("✓ Disconnected from SFTP server")
            return True
        except Exception as e:
            print(f"✗ Disconnection failed: {str(e)}")
            return False
    
    def read_file(self, file_path: str) -> Optional[str]:
        """Read file content from remote server"""
        if not self.connected:
            print("✗ Not connected to SFTP server")
            return None
        
        try:
            with self.sftp_client.file(file_path, 'r') as f:
                content = f.read().decode('utf-8')
            print(f"✓ File read: {file_path}")
            return content
        except Exception as e:
            print(f"✗ Failed to read file: {str(e)}")
            return None
    
    def write_file(self, file_path: str, content: str) -> bool:
        """Write content to file on remote server"""
        if not self.connected:
            print("✗ Not connected to SFTP server")
            return False
        
        try:
            with self.sftp_client.file(file_path, 'w') as f:
                f.write(content.encode('utf-8'))
            print(f"✓ File written: {file_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to write file: {str(e)}")
            return False
    
    def list_files(self, directory: str) -> Optional[List[str]]:
        """List files in remote directory"""
        if not self.connected:
            print("✗ Not connected to SFTP server")
            return None
        
        try:
            files = self.sftp_client.listdir(directory)
            print(f"✓ Listed {len(files)} items in {directory}")
            return files
        except Exception as e:
            print(f"✗ Failed to list directory: {str(e)}")
            return None
    
    def delete_file(self, file_path: str) -> bool:
        """Delete file on remote server"""
        if not self.connected:
            print("✗ Not connected to SFTP server")
            return False
        
        try:
            self.sftp_client.remove(file_path)
            print(f"✓ File deleted: {file_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to delete file: {str(e)}")
            return False
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload local file to remote server"""
        if not self.connected:
            print("✗ Not connected to SFTP server")
            return False
        
        try:
            self.sftp_client.put(local_path, remote_path)
            print(f"✓ File uploaded: {local_path} → {remote_path}")
            return True
        except Exception as e:
            print(f"✗ Upload failed: {str(e)}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from remote server to local"""
        if not self.connected:
            print("✗ Not connected to SFTP server")
            return False
        
        try:
            self.sftp_client.get(remote_path, local_path)
            print(f"✓ File downloaded: {remote_path} → {local_path}")
            return True
        except Exception as e:
            print(f"✗ Download failed: {str(e)}")
            return False


class HTTPFileAccess(RemoteFileAccess):
    """HTTP/HTTPS for remote file access via web protocols"""
    
    def __init__(self, base_url: str, auth: Optional[tuple] = None, 
                 headers: Optional[dict] = None):
        """
        Initialize HTTP/HTTPS connection parameters
        
        Args:
            base_url: Base URL of the remote server
            auth: Tuple of (username, password) for basic auth
            headers: Custom headers for requests
        """
        super().__init__()
        self.base_url = base_url.rstrip('/')
        self.auth = auth
        self.headers = headers or {}
        self.connected = True  # HTTP doesn't require persistent connection
    
    def connect(self) -> bool:
        """Verify HTTP connection"""
        try:
            response = requests.head(self.base_url, auth=self.auth, 
                                    headers=self.headers, timeout=5)
            if response.status_code < 500:
                self.connected = True
                print(f"✓ Connected to {self.base_url}")
                return True
        except Exception as e:
            print(f"✗ HTTP Connection failed: {str(e)}")
            return False
        
        return False
    
    def disconnect(self) -> bool:
        """HTTP doesn't maintain persistent connections"""
        self.connected = True
        return True
    
    def read_file(self, file_path: str) -> Optional[str]:
        """Read file from HTTP server"""
        try:
            url = f"{self.base_url}/{file_path.lstrip('/')}"
            response = requests.get(url, auth=self.auth, 
                                   headers=self.headers, timeout=10)
            response.raise_for_status()
            print(f"✓ File read: {file_path}")
            return response.text
        except Exception as e:
            print(f"✗ Failed to read file: {str(e)}")
            return None
    
    def write_file(self, file_path: str, content: str) -> bool:
        """Write file to HTTP server (requires PUT/POST support)"""
        try:
            url = f"{self.base_url}/{file_path.lstrip('/')}"
            response = requests.put(url, data=content.encode('utf-8'),
                                   auth=self.auth, headers=self.headers, 
                                   timeout=10)
            response.raise_for_status()
            print(f"✓ File written: {file_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to write file: {str(e)}")
            return False
    
    def list_files(self, directory: str) -> Optional[List[str]]:
        """List files in HTTP directory"""
        try:
            url = f"{self.base_url}/{directory.lstrip('/')}"
            response = requests.get(url, auth=self.auth, 
                                   headers=self.headers, timeout=10)
            response.raise_for_status()
            # Parse JSON response or HTML listing
            if response.headers.get('content-type', '').startswith('application/json'):
                data = response.json()
                files = [item['name'] for item in data] if isinstance(data, list) else []
            else:
                files = []
            print(f"✓ Listed files in {directory}")
            return files
        except Exception as e:
            print(f"✗ Failed to list directory: {str(e)}")
            return None
    
    def delete_file(self, file_path: str) -> bool:
        """Delete file from HTTP server (requires DELETE support)"""
        try:
            url = f"{self.base_url}/{file_path.lstrip('/')}"
            response = requests.delete(url, auth=self.auth, 
                                      headers=self.headers, timeout=10)
            response.raise_for_status()
            print(f"✓ File deleted: {file_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to delete file: {str(e)}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from HTTP server"""
        try:
            url = f"{self.base_url}/{remote_path.lstrip('/')}"
            response = requests.get(url, auth=self.auth, 
                                   headers=self.headers, timeout=10)
            response.raise_for_status()
            
            with open(local_path, 'wb') as f:
                f.write(response.content)
            print(f"✓ File downloaded: {remote_path} → {local_path}")
            return True
        except Exception as e:
            print(f"✗ Download failed: {str(e)}")
            return False


class LocalFileAccess(RemoteFileAccess):
    """Local file system access with same interface"""
    
    def __init__(self, base_path: str = "/"):
        """Initialize local file access"""
        super().__init__()
        self.base_path = base_path
        self.connected = True
    
    def connect(self) -> bool:
        """Verify base path exists"""
        if os.path.exists(self.base_path):
            self.connected = True
            print(f"✓ Local path accessible: {self.base_path}")
            return True
        print(f"✗ Local path not found: {self.base_path}")
        return False
    
    def disconnect(self) -> bool:
        """No-op for local filesystem"""
        return True
    
    def read_file(self, file_path: str) -> Optional[str]:
        """Read local file"""
        try:
            full_path = os.path.join(self.base_path, file_path.lstrip('/'))
            with open(full_path, 'r') as f:
                content = f.read()
            print(f"✓ File read: {file_path}")
            return content
        except Exception as e:
            print(f"✗ Failed to read file: {str(e)}")
            return None
    
    def write_file(self, file_path: str, content: str) -> bool:
        """Write to local file"""
        try:
            full_path = os.path.join(self.base_path, file_path.lstrip('/'))
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'w') as f:
                f.write(content)
            print(f"✓ File written: {file_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to write file: {str(e)}")
            return False
    
    def list_files(self, directory: str) -> Optional[List[str]]:
        """List local directory contents"""
        try:
            full_path = os.path.join(self.base_path, directory.lstrip('/'))
            files = os.listdir(full_path)
            print(f"✓ Listed {len(files)} items in {directory}")
            return files
        except Exception as e:
            print(f"✗ Failed to list directory: {str(e)}")
            return None
    
    def delete_file(self, file_path: str) -> bool:
        """Delete local file"""
        try:
            full_path = os.path.join(self.base_path, file_path.lstrip('/'))
            if os.path.isfile(full_path):
                os.remove(full_path)
            print(f"✓ File deleted: {file_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to delete file: {str(e)}")
            return False


# Example Usage
if __name__ == "__main__":
    print("=== Remote File Access Examples ===\n")
    
    # Example 1: Local File Access
    print("1. Local File Access:")
    local = LocalFileAccess("/home/user")
    local.connect()
    local.write_file("test.txt", "Hello, Remote Files!")
    content = local.read_file("test.txt")
    print(f"Content: {content}\n")
    
    # Example 2: SFTP Access
    print("2. SFTP Remote Access:")
    sftp = SFTPFileAccess(
        host="example.com",
        username="user",
        password="password"
    )
    if sftp.connect():
        files = sftp.list_files("/home/user")
        sftp.disconnect()
    print()
    
    # Example 3: HTTP/HTTPS Access
    print("3. HTTP Remote Access:")
    http = HTTPFileAccess(
        base_url="https://api.example.com",
        auth=("user", "pass")
    )
    http.connect()
    content = http.read_file("data/config.json")
    print(f"Content: {content}\n")

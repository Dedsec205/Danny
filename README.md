# Danny
Project 1 : # 🛡️ Automated Reconnaissance & Reporting Tool (Kali → Metasploitable Lab)

This project is a simple "cybersecurity lab automation tool" built in a controlled virtual environment using Kali Linux and Metasploitable 

2. It performs reconnaissance on vulnerable systems and automatically generates a clean HTML vulnerability report.

---

## 🧠 Features
- Runs Nmap for service and version detection.
- Uses  Nikto for web vulnerability scanning.
- Combines both results into a single HTML report using a Python script (`reporter.py`).
- Safe, beginner-friendly project for learning network scanning and reporting.

---

## 🧰 Tools & Environment
- Kali Linux (Attacker VM)
-  Metasploitable 2 (Target VM)
-  VirtualBox (Network simulation)
-  Nmap , Nikto, Python 3

---

## 📊 Workflow
1. Kali scans Metasploitable using:
   >nmap -sV -oX nmap_scan.xml 192.168.56.101
   nikto -h http://192.168.56.101 -o nikto_output.txt

2. Run the python script to merge results:

>python3 reporter.py nmap_scan.xml nikto_output.txt myreport.html

The result can be shown in this picture : 



3. Open the generated report in browser :
>firefox myreport.html

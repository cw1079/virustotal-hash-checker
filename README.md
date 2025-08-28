# 🦠 VirusTotal Hash Checker (Python)

## 📌 Overview
This project is a simple **Python script** that uses the [VirusTotal API v3](https://developers.virustotal.com/reference/overview) to retrieve malware scan reports for a given file hash (SHA-256, SHA-1, or MD5).  

It takes a hash as input, queries VirusTotal, and saves the results as a JSON file for further analysis.  

---

## ⚡ Features
- Accepts **SHA-256**, **SHA-1**, or **MD5** file hashes  
- Retrieves scan reports via the VirusTotal API  
- Saves the response to `my_data.json`  
- Provides clear error handling if the API call fails  

---

## 🛠️ Requirements
- Python **3.7+**  
- `requests` library  
- A **VirusTotal API Key** (you can get one by signing up at [virustotal.com](https://www.virustotal.com/))  

Install dependencies:
```bash
pip install requests

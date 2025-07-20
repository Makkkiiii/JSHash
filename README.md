# 🔓 JSHash - Advanced Hash Cracking Tool

<div align="center">

![Hash Cracking](https://img.shields.io/badge/Hash-Cracking-red?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)
![John](https://img.shields.io/badge/John-The%20Ripper-orange?style=for-the-badge)
![Hashcat](https://img.shields.io/badge/Hashcat-Supported-green?style=for-the-badge)

</div>

## 🎯 Overview

**JSHash** is a comprehensive hash cracking tool that supports multiple file formats, hash types, and cracking engines. It provides an intuitive interface for extracting hashes from protected files and cracking them using industry-standard tools like John the Ripper and Hashcat.

<div align="center">

```
╭─────────────────────────────────────────────────────╮
│                                                     │
│  🔓 JSHash - One Tool to Crack Them All 🔓        │
│                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Extract     │  │ Detect      │  │ Crack       │ │
│  │ Hashes      │→ │ Hash Type   │→ │ Passwords   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│                                                     │
╰─────────────────────────────────────────────────────╯
```

</div>

## ✨ Features

### 🔐 **File Format Support**
- **Archives**: ZIP, 7Z, RAR
- **Documents**: PDF, DOC, DOCX, XLS, XLSX
- **System Files**: /etc/shadow, /etc/passwd

### 🎯 **Hash Detection & Cracking**
- **Auto-Detection**: Intelligent hash type identification
- **Manual Input**: Custom format specification
- **Skip Detection**: Use tool defaults for faster processing
- **Multiple Engines**: John the Ripper & Hashcat support

### 🧠 **Smart Features**
- **Resume Support**: Continue interrupted cracking sessions
- **Multi-Threading**: Optimized CPU usage
- **Wordlist Management**: Built-in popular wordlists
- **Result Logging**: Automatic result saving

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/Makkkiiii/JSHash.git
cd jshash

# Install dependencies
pip install colorama hashid

# Make executable
chmod +x jshash.py
```

### 📋 **Prerequisites**
- Python 3.x
- John the Ripper
- Hashcat (optional)
- Required Python packages: `colorama`, `hashid`

## 🚀 Usage

### **Quick Start**
```bash
python3 jshash.py
```

### **Supported Modes**

#### 🗄️ **Mode 1: Archive/File Cracking**
Extract hashes from protected files and crack them.

#### 👤 **Mode 2: Shadow File Cracking**
Crack Linux user passwords from shadow files.

#### 📄 **Mode 3: Direct Hash Cracking**
Crack hashes from existing hash files.

## 📊 Sample Output

<details>
<summary>🎬 <strong>Click to see demo</strong></summary>

```
🔓 Hash Cracker | Supports ZIP/PDF/7z/Office + John/Hashcat + Shadow Cracking

Choose mode:
1) Crack from archive/file (extract hash)
2) Crack from /etc/shadow
3) Crack directly from a hash file

Choose option [1/2/3]: 1

Enter path to target file (e.g., secret.zip): /home/user/secret.zip

[✔] Found file: /home/user/secret.zip

Enter output filename for hash (e.g., zip.hash): secret.hash

[*] Extracting hash using zip2john...
[✔] Hash saved to file: secret.hash

Choose cracking tool (john/hashcat): john

📚 Available Wordlists:
 1. rockyou.txt -> /usr/share/wordlists/rockyou.txt
 2. unix_users.txt -> /usr/share/metasploit-framework/data/wordlists/unix_users.txt
 3. xato-net-10-million.txt -> /usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt
 4. scraped-JWT-secrets.txt -> /usr/share/seclists/Passwords/scraped-JWT-secrets.txt
 5. Custom path

Choose wordlist [1-5]: 1
[✔] Selected wordlist: /usr/share/wordlists/rockyou.txt

Your system has 8 CPU threads available.

How many CPU threads do you want to use for cracking? [1-8]: 4

[?] Hash format detection options:
1) Auto-detect hash format
2) Skip detection and input format manually
3) Skip detection (use tool defaults)

Choose option [1/2/3]: 1

[*] Possible hash types detected:
 1. PKZIP | John format: pkzip | Hashcat mode: 17200
 2. ZIP | John format: zip | Hashcat mode: N/A

Choose format number, 'm' for manual input, or 's' to skip: 1
[✔] Selected John format: pkzip, Hashcat mode: 17200

[*] Starting cracking with John (resume supported)...

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (secret.zip)
1g 0:00:00:02 DONE (2025-07-20 14:30) 0.4761g/s 2440Kp/s 2440Kc/s 2440KC/s ..

=============== Cracked Passwords ===============

secret.zip:password123

=============================================

🎉 Done. Check cracked_results.txt for saved output.
```

</details>

## 🎨 Hash Format Detection

JSHash provides three flexible options for hash format detection:

### 🔍 **Auto-Detection (Recommended)**
- Uses HashID library for intelligent detection
- Shows top 5 possible hash types
- Displays corresponding John/Hashcat formats

### ✋ **Manual Input**
- Direct format specification
- Supports John formats: `raw-md5`, `bcrypt`, `nt`, etc.
- Supports Hashcat modes: `0`, `1000`, `3200`, etc.

### ⚡ **Skip Detection**
- Fastest option for experienced users
- Uses tool defaults for format detection
- Ideal for batch processing

## 📁 Supported Hash Types

<div align="center">

| Hash Type | John Format | Hashcat Mode | Description |
|-----------|-------------|--------------|-------------|
| MD5 | `raw-md5` | `0` | Standard MD5 |
| SHA-1 | `raw-sha1` | `100` | SHA-1 hash |
| SHA-256 | `raw-sha256` | `1400` | SHA-256 hash |
| SHA-512 | `raw-sha512` | `1700` | SHA-512 hash |
| bcrypt | `bcrypt` | `3200` | bcrypt hash |
| NTLM | `nt` | `1000` | Windows NTLM |
| MySQL5 | `mysql-sha1` | `300` | MySQL v5.x |

</div>

## 🗂️ Built-in Wordlists

| Wordlist | Path | Size | Description |
|----------|------|------|-------------|
| **rockyou.txt** | `/usr/share/wordlists/rockyou.txt` | ~14M | Most popular passwords |
| **unix_users.txt** | `/usr/share/metasploit-framework/data/wordlists/unix_users.txt` | Small | Common usernames |
| **xato-net-10-million.txt** | `/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt` | Large | Top 100K passwords |
| **scraped-JWT-secrets.txt** | `/usr/share/seclists/Passwords/scraped-JWT-secrets.txt` | Medium | JWT secrets |

## 🔧 Advanced Features

### 🔄 **Resume Support**
Both John the Ripper and Hashcat support resuming interrupted sessions automatically.

### ⚡ **Multi-Threading**
- Automatic CPU thread detection
- Optimized workload distribution
- Configurable thread usage

### 📝 **Logging & Results**
- All operations logged to `crack.log`
- Cracked passwords saved to `cracked_results.txt`
- Colored terminal output for better readability

## 🎯 Use Cases

### 🔐 **Penetration Testing**
- Password recovery for client files
- Security assessment of password policies
- Hash cracking competitions

### 🛡️ **Digital Forensics**
- Evidence file password recovery
- System compromise investigation
- Malware analysis support

### 🎓 **Educational**
- Learning hash cracking techniques
- Understanding password security
- Cybersecurity training

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes** and **authorized penetration testing** only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

[⭐ Star this repo](https://github.com/yourusername/jshash) | [🐛 Report Bug](https://github.com/yourusername/jshash/issues) | [💡 Request Feature](https://github.com/yourusername/jshash/issues)

</div>

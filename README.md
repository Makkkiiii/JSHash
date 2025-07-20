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

### 🔐 **Enhanced File Format Support**
- **Archives**: ZIP, 7Z, RAR
- **Documents**: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
- **Database/Password Managers**: KeePass (KDBX, KeePassXC), GPG, PGP, ASC
- **Disk Encryption**: DMG, LUKS, BitLocker, TrueCrypt
- **Network/Protocol**: PCAP, CAP, HCCAP, HCCAPX
- **SSH/Key Formats**: SSH keys, PEM, PPK (PuTTY)
- **Other Formats**: Password Safe, Bitcoin Wallet, iTunes Backup, Mozilla, Keychain
- **System Files**: /etc/shadow, /etc/passwd

### 🧠 **Intelligent Hash Detection**
- **Multi-Method Detection**: Combines pattern-based detection + HashID
- **Hash Validation**: Validates hashes against expected formats before cracking
- **Confidence Scoring**: Shows High/Medium confidence levels for detections
- **Context-Aware Suggestions**: Enhanced format recommendations
- **Advanced Pattern Recognition**: Uses regex patterns for common hash types

### 📚 **Smart Wordlist Management**
- **Hash-Type Recommendations**: Suggests optimal wordlists based on detected hash type
- **Wordlist Merging**: Combine multiple wordlists with deduplication
- **Smart Auto-Selection**: Automatically selects best wordlists for hash type
- **Custom Wordlist Support**: Add your own wordlist files
- **Built-in Popular Lists**: rockyou.txt, common-passwords, darkweb2017, etc.

### 🔧 **Advanced Attack Methods**
- **Rule-Based Attacks**: Support for John the Ripper rules (best64, dive, jumbo, etc.)
- **Hybrid Attacks**: Wordlist + mask pattern combinations
- **Multi-Threading**: Optimized CPU usage with configurable threads
- **Resume Support**: Continue interrupted cracking sessions
- **Attack Strategy Selection**: Choose between different attack types

### 🎯 **Cracking Engine Support**
- **John the Ripper**: Full support with advanced features
- **Hashcat**: GPU-accelerated cracking support
- **Auto-Detection**: Intelligent hash type identification
- **Manual Override**: Custom format specification
- **Format Validation**: Ensures compatibility before cracking

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/Makkkiiii/JSHash.git
cd jshash

# Install dependencies
pip install -r requirements.txt
# or manually:
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
Extract hashes from protected files and crack them. Now supports 25+ file formats!

#### 👤 **Mode 2: Shadow File Cracking**
Crack Linux user passwords from shadow files with unshadow support.

#### 📄 **Mode 3: Direct Hash Cracking**
Crack hashes from existing hash files with intelligent detection.

#### 📋 **Mode 4: View Supported Formats**
Display all supported file formats organized by category with examples.

## 📊 Sample Output

<details>
<summary>🎬 <strong>Click to see demo</strong></summary>

```
🔓 Hash Cracker | Supports ZIP/PDF/7z/Office + John/Hashcat + Shadow Cracking

Choose mode:
1) Crack from archive/file (extract hash)
2) Crack from /etc/shadow
3) Crack directly from a hash file
4) View supported file formats

Choose option [1/2/3/4]: 1

Enter path to target file (e.g., secret.zip): /home/user/secret.zip

[✔] Found file: /home/user/secret.zip

Enter output filename for hash (e.g., zip.hash): secret.hash

[*] Extracting hash using zip2john...
[✔] Hash saved to file: secret.hash

Choose cracking tool (john/hashcat): john

[#] Enhanced Hash Detection System
1) Auto-detect hash format (Multiple detection methods)
2) Skip detection and input format manually
3) Skip detection (use tool defaults)

Choose option [1/2/3]: 1

[*] Running multiple detection methods...
[*] Pattern detection found: PKZIP
[*] HashID detected 2 possible types

[*] Combined detection results:
 1. PKZIP [Pattern] (High confidence)
    John: pkzip | Hashcat: 17200
 2. ZIP [HashID] (Medium confidence)
    John: zip | Hashcat: N/A

[*] Hash validation for PKZIP: ✓ Valid

Choose format number, 'm' for manual input, or 's' to skip: 1
[✔] Selected: PKZIP | John: pkzip | Hashcat: 17200

📚 Smart Wordlist Selection:
💡 Recommended for PKZIP: rockyou.txt, common-passwords.txt

Available options:
1) Use individual wordlist
2) Merge multiple wordlists
3) Smart selection (recommended for detected hash type)

Choose option [1/2/3]: 3
[*] Merging 2 wordlists...
[✔] Merged wordlist created: merged_wordlist_pkzip.txt
[*] Original lines: 14344392, Unique passwords: 14344391

Your system has 8 CPU threads available.

How many CPU threads do you want to use for cracking? [1-8]: 4

🔧 John the Ripper Attack Options:
1) Wordlist attack only
2) Wordlist + Rules attack
3) Hybrid attack (wordlist + mask)

Choose attack type [1/2/3]: 2

📋 Available Rule Files:
 1. best64 -> /usr/share/john/rules/best64.rule [✓]
 2. dive -> /usr/share/john/rules/dive.rule [✓]
 3. jumbo -> /usr/share/john/rules/jumbo.rule [✓]
 4. Use all available rules
 5. Custom rule file

Choose rule [1-5]: 1
[*] Using rule: best64

[*] Starting John the Ripper attack (resume supported)...
[*] Command: john --wordlist=merged_wordlist_pkzip.txt --rules=/usr/share/john/rules/best64.rule --format=pkzip --fork=4 secret.hash

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (secret.zip)
1g 0:00:00:03 DONE (2025-07-20 14:30) 0.3333g/s 4880Kp/s 4880Kc/s 4880KC/s ..

=============== Cracked Passwords ===============

secret.zip:password123

=============================================

🎉 Done. Check cracked_results.txt for saved output.
```

</details>

## 🎨 Enhanced Hash Format Detection

JSHash provides advanced hash detection with multiple validation methods:

### 🔍 **Multi-Method Auto-Detection (Recommended)**
- **Pattern Recognition**: Uses regex patterns for accurate detection
- **HashID Integration**: Leverages HashID library for comprehensive analysis
- **Confidence Scoring**: Shows High/Medium confidence levels
- **Hash Validation**: Validates format before cracking starts
- **Combined Results**: Merges results from multiple detection methods

### ✋ **Manual Input**
- Direct format specification for experts
- Supports John formats: `raw-md5`, `bcrypt`, `nt`, `pkzip`, etc.
- Supports Hashcat modes: `0`, `1000`, `3200`, `17200`, etc.
- Custom format override capabilities

### ⚡ **Skip Detection**
- Fastest option for experienced users
- Uses tool defaults for format detection
- Ideal for batch processing and automation

## 📁 Comprehensive File Format Support

<div align="center">

### **25+ Supported File Formats**

| Category | Formats | Tools Used |
|----------|---------|------------|
| **Archive Formats** | ZIP, 7Z, RAR | zip2john, 7z2john.pl, rar2john |
| **Document Formats** | PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX | pdf2john.pl, office2john.py |
| **Database/Password Managers** | KeePass (KDBX), KeePassXC, GPG, PGP, ASC | keepass2john, gpg2john |
| **Disk Encryption** | DMG, LUKS, BitLocker, TrueCrypt | dmg2john, luks2john, bitlocker2john, truecrypt2john.py |
| **Network/Protocol** | PCAP, CAP, HCCAP, HCCAPX | wpapcap2john, hccap2john, hccapx2john |
| **SSH/Key Formats** | SSH, PEM, PPK (PuTTY) | ssh2john.py, putty2john |
| **Other Formats** | Password Safe, Bitcoin Wallet, iTunes, Mozilla, Keychain | pwsafe2john, bitcoin2john.py, itunes_backup2john.py, mozilla2john.py, keychain2john |

</div>

### **Smart Format Detection**
- Automatic file type recognition by extension
- Interactive format assistance when unsupported files are encountered  
- Comprehensive format listing with examples on demand

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

## 🗂️ Smart Wordlist Management

### **Built-in Wordlists**

| Wordlist | Path | Size | Description |
|----------|------|------|-------------|
| **rockyou.txt** | `/usr/share/wordlists/rockyou.txt` | ~14M | Most popular passwords |
| **unix_users.txt** | `/usr/share/metasploit-framework/data/wordlists/unix_users.txt` | Small | Common usernames |
| **xato-net-10-million.txt** | `/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt` | Large | Top 100K passwords |
| **scraped-JWT-secrets.txt** | `/usr/share/seclists/Passwords/scraped-JWT-secrets.txt` | Medium | JWT secrets |
| **common-passwords.txt** | `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt` | Large | Common passwords |
| **darkweb2017-top10000.txt** | `/usr/share/seclists/Passwords/darkweb2017-top10000.txt` | Medium | Dark web leaked passwords |

### **Smart Features**
- **Hash-Type Recommendations**: Automatically suggests best wordlists for detected hash types
- **Wordlist Merging**: Combine multiple wordlists with automatic deduplication
- **Smart Auto-Selection**: Intelligently selects optimal wordlists based on hash analysis
- **Custom Integration**: Easy addition of your own wordlist files

### **Hash-Type Specific Recommendations**
- **NTLM**: rockyou.txt + common-passwords.txt
- **MD5**: rockyou.txt + xato-net-10-million.txt  
- **SHA-1**: rockyou.txt + darkweb2017-top10000.txt
- **MySQL5**: unix_users.txt + rockyou.txt
- **bcrypt**: rockyou.txt + common-passwords.txt

## 🔧 Advanced Attack Methods

### **John the Ripper Enhanced Features**

#### 🎯 **Attack Types**
1. **Wordlist Attack**: Standard dictionary-based attack
2. **Rule-Based Attack**: Wordlist + transformation rules for maximum coverage
3. **Hybrid Attack**: Wordlist + mask patterns for targeted attacks

#### 📋 **Built-in Rule Files**
- **best64.rule**: Most effective 64 rules for password transformation
- **dive.rule**: Deep rule set for comprehensive coverage  
- **jumbo.rule**: Large rule set with extensive transformations
- **single.rule**: Single-word attack rules
- **wordlist.rule**: Basic wordlist transformation rules

#### 🎭 **Mask Attack Support**
- Custom mask patterns (e.g., `?d?d?d` for 3 digits)
- Hybrid wordlist + mask combinations
- Flexible pattern definitions

### **Performance Optimizations**
- **Smart Threading**: Automatic CPU core detection and optimization
- **Resume Support**: Continue interrupted sessions automatically
- **Workload Management**: Intelligent task distribution
- **Memory Optimization**: Efficient wordlist handling and deduplication

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
- Forensic analysis of encrypted containers
- Security research and education

### 🏢 **Enterprise Security**
- Password policy compliance testing
- Recovery of lost archive passwords
- Security audit of legacy systems
- Training and awareness programs

## ⚡ Performance Optimizations

### **Speed Enhancements**
- **Smart Wordlist Selection**: Automatically chooses optimal wordlists for each hash type
- **Wordlist Deduplication**: Removes duplicate passwords to reduce processing time
- **Multi-Threading**: Optimized CPU core utilization for maximum performance
- **Rule-Based Attacks**: Multiply password coverage without increasing wordlist size
- **Hash Validation**: Prevents wasted time on malformed hashes

### **Memory Optimizations**  
- **Efficient Wordlist Handling**: Streaming processing for large wordlists
- **Smart Caching**: Intelligent caching of frequently used data
- **Resource Management**: Automatic cleanup and memory management

### **Attack Strategy Optimization**
- **Hybrid Attacks**: Combine multiple attack methods for better success rates
- **Progressive Complexity**: Start with simple attacks before complex ones
- **Resume Capability**: Never lose progress on long-running sessions

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes** and **authorized penetration testing** only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


---

<div align="center">

**Made with ❤️ for the cybersecurity community**

[⭐ Star this repo](https://github.com/yourusername/jshash) | [🐛 Report Bug](https://github.com/yourusername/jshash/issues) | [💡 Request Feature](https://github.com/yourusername/jshash/issues)

</div>

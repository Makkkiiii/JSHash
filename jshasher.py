#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import logging
from colorama import Fore, Style, init
from hashid import HashID
import re
import hashlib

init(autoreset=True)
logging.basicConfig(filename='crack.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Office document formats that use the same tool
OFFICE_FORMATS = ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
KEEPASS_FORMATS = ['kdbx', 'keepassxc']
TRUECRYPT_FORMATS = ['tc', 'truecrypt']

TOOL_MAP = {
    # Archive formats
    'zip': 'zip2john',
    '7z': '7z2john.pl',
    'rar': 'rar2john',
    
    # Document formats
    'pdf': 'pdf2john.pl',
    
    # Database/Password manager formats
    'gpg': 'gpg2john',
    
    # Disk encryption
    'dmg': 'dmg2john',
    'luks': 'luks2john',
    'bitlocker': 'bitlocker2john',
    
    # Network/Protocol formats
    'pcap': 'wpapcap2john',
    'cap': 'wpapcap2john',
    'hccap': 'hccap2john',
    'hccapx': 'hccapx2john',
    
    # SSH/Key formats
    'ssh': 'ssh2john.py',
    'pem': 'ssh2john.py',
    'ppk': 'putty2john',
    
    # Other formats
    'psafe3': 'pwsafe2john',
    'wallet': 'bitcoin2john.py',
    'itunes': 'itunes_backup2john.py',
    'mozilla': 'mozilla2john.py',
    'keychain': 'keychain2john',
    'pgp': 'gpg2john',
    'asc': 'gpg2john',
}

# Add office formats dynamically
for fmt in OFFICE_FORMATS:
    TOOL_MAP[fmt] = 'office2john.py'

# Add KeePass formats dynamically  
for fmt in KEEPASS_FORMATS:
    TOOL_MAP[fmt] = 'keepass2john'

# Add TrueCrypt formats dynamically
for fmt in TRUECRYPT_FORMATS:
    TOOL_MAP[fmt] = 'truecrypt2john.py'

WORDLISTS = {
    'rockyou.txt': '/usr/share/wordlists/rockyou.txt',
    'unix_users.txt': '/usr/share/metasploit-framework/data/wordlists/unix_users.txt',
    'xato-net-10-million.txt': '/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt',
    'scraped-JWT-secrets.txt': '/usr/share/seclists/Passwords/scraped-JWT-secrets.txt',
    'common-passwords.txt': '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
    'darkweb2017-top10000.txt': '/usr/share/seclists/Passwords/darkweb2017_top10000.txt',
}

# John the Ripper rule files
JOHN_RULES = {
    'best64': '/usr/share/john/rules/best64.rule',
    'dive': '/usr/share/john/rules/dive.rule', 
    'jumbo': '/usr/share/john/rules/jumbo.rule',
    'single': '/usr/share/john/rules/single.rule',
    'wordlist': '/usr/share/john/rules/wordlist.rule',
}

# Smart wordlist recommendations based on hash type
HASH_TYPE_WORDLISTS = {
    'NTLM': ['rockyou.txt', 'common-passwords.txt'],
    'MD5': ['rockyou.txt', 'xato-net-10-million.txt'],
    'SHA-1': ['rockyou.txt', 'darkweb2017-top10000.txt'],
    'SHA-256': ['rockyou.txt', 'common-passwords.txt'],
    'bcrypt': ['rockyou.txt', 'common-passwords.txt'],
    'MySQL5': ['unix_users.txt', 'rockyou.txt'],
    'default': ['rockyou.txt', 'common-passwords.txt']
}

HASH_FORMATS = {
    'MD5': ('raw-md5', '0'),
    'MD4': ('raw-md4', '900'),
    'SHA-1': ('raw-sha1', '100'),
    'SHA-256': ('raw-sha256', '1400'),
    'SHA-512': ('raw-sha512', '1700'),
    'bcrypt': ('bcrypt', '3200'),
    'NTLM': ('nt', '1000'),
    'SHA-1(HMAC)': ('hmac-sha1', None),
    'MySQL323': ('mysql', '200'),
    'MySQL5': ('mysql-sha1', '300'),
    # Add more mappings as needed
}

def colored(msg, color=Fore.CYAN):
    return f"{color}{msg}{Style.RESET_ALL}"

def advanced_hash_detection(hash_content):
    """Advanced hash detection using multiple methods"""
    hash_content = hash_content.strip()
    
    # Pattern-based detection
    patterns = {
        'MD5': r'^[a-f0-9]{32}$',
        'SHA-1': r'^[a-f0-9]{40}$', 
        'SHA-256': r'^[a-f0-9]{64}$',
        'SHA-512': r'^[a-f0-9]{128}$',
        'NTLM': r'^[a-f0-9]{32}$',
        'bcrypt': r'^\$2[ayb]\$.{56}$',
        'MySQL5': r'^\*[A-F0-9]{40}$',
        'DES': r'^[a-zA-Z0-9./]{13}$',
        'Blowfish': r'^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$',
    }
    
    detected = []
    for hash_type, pattern in patterns.items():
        if re.match(pattern, hash_content, re.IGNORECASE):
            detected.append(hash_type)
    
    return detected

def validate_hash_format(hash_content, expected_format):
    """Validate hash against expected format"""
    try:
        if expected_format in ['MD5', 'NTLM'] and len(hash_content.strip()) == 32:
            return True
        elif expected_format == 'SHA-1' and len(hash_content.strip()) == 40:
            return True
        elif expected_format == 'SHA-256' and len(hash_content.strip()) == 64:
            return True
        elif expected_format == 'SHA-512' and len(hash_content.strip()) == 128:
            return True
        elif expected_format == 'bcrypt' and hash_content.startswith('$2'):
            return True
        return False
    except:
        return False

def get_smart_wordlist_recommendations(hash_type):
    """Get smart wordlist recommendations based on detected hash type"""
    return HASH_TYPE_WORDLISTS.get(hash_type, HASH_TYPE_WORDLISTS['default'])

def merge_wordlists(wordlist_paths, output_path):
    """Merge multiple wordlists and remove duplicates"""
    print(colored(f"[*] Merging {len(wordlist_paths)} wordlists...", Fore.CYAN))
    
    unique_passwords = set()
    total_lines = 0
    
    for wordlist in wordlist_paths:
        if os.path.isfile(wordlist):
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        password = line.strip()
                        if password and len(password) <= 256:  # Reasonable length limit
                            unique_passwords.add(password)
                            total_lines += 1
            except Exception as e:
                print(colored(f"[!] Error reading {wordlist}: {e}", Fore.RED))
    
    # Write merged wordlist
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for password in sorted(unique_passwords):
                f.write(f"{password}\n")
        
        print(colored(f"[✔] Merged wordlist created: {output_path}", Fore.GREEN))
        print(colored(f"[*] Original lines: {total_lines}, Unique passwords: {len(unique_passwords)}", Fore.YELLOW))
        return output_path
    except Exception as e:
        print(colored(f"[!] Error creating merged wordlist: {e}", Fore.RED))
        return None

def display_supported_formats():
    print()
    print(colored("📋 Supported File Formats and Tools:", Fore.CYAN))
    print(colored("=" * 50, Fore.CYAN))
    
    # Group formats by category for better display
    categories = {
        "Archive Formats": ["zip", "7z", "rar"],
        "Document Formats": ["pdf"] + OFFICE_FORMATS,
        "Database/Password Managers": ["gpg", "pgp", "asc"] + KEEPASS_FORMATS,
        "Disk Encryption": ["dmg", "luks", "bitlocker"] + TRUECRYPT_FORMATS,
        "Network/Protocol": ["pcap", "cap", "hccap", "hccapx"],
        "SSH/Key Formats": ["ssh", "pem", "ppk"],
        "Other Formats": ["psafe3", "wallet", "itunes", "mozilla", "keychain"]
    }
    
    for category, formats in categories.items():
        print(colored(f"\n{category}:", Fore.YELLOW))
        for fmt in formats:
            tool = TOOL_MAP.get(fmt, "Unknown")
            print(f"  • {fmt} → {tool}")
    
    print(colored("\n" + "=" * 50, Fore.CYAN))
    print(colored("Example usage: secret.zip, document.pdf, database.kdbx, etc.\n", Fore.GREEN))

def prompt_file(msg):
    while True:
        print()
        path = input(colored(msg)).strip()
        if os.path.isfile(path):
            print(colored(f"[✔] Found file: {path}\n", Fore.GREEN))
            return path
        print(colored("[!] File does not exist. Try again.\n", Fore.RED))

def prompt_nonempty(msg):
    while True:
        print()
        val = input(colored(msg)).strip()
        if val:
            print()
            return val
        print(colored("[!] Input cannot be empty. Try again.\n", Fore.RED))

def get_hash_tool(file_path):
    ext = file_path.split('.')[-1].lower()
    return TOOL_MAP.get(ext)

def extract_hash(file_path, output_file):
    tool = get_hash_tool(file_path)
    if not tool:
        print()
        print(colored("[!] Unsupported file type.", Fore.RED))
        print(colored("Would you like to see all supported formats? (y/n): ", Fore.CYAN), end="")
        show_formats = input().strip().lower()
        if show_formats in ['y', 'yes']:
            display_supported_formats()
        else:
            # Create a quick list of supported extensions
            supported_exts = sorted(list(TOOL_MAP.keys()))
            print(colored(f"Supported extensions: {', '.join(supported_exts[:15])}{'...' if len(supported_exts) > 15 else ''}\n", Fore.YELLOW))
        return False

    print()
    print(colored(f"[*] Extracting hash using {tool}...", Fore.CYAN))
    try:
        tool_exec = shutil.which(tool) or f"./{tool}"
        result = subprocess.check_output([tool_exec, file_path], stderr=subprocess.STDOUT)
        with open(output_file, 'w') as f:
            f.write(result.decode())
        print(colored(f"[✔] Hash saved to file: {output_file}\n", Fore.GREEN))
        return True
    except Exception as e:
        print()
        print(colored(f"[!] Failed to extract hash: {str(e)}\n", Fore.RED))
        return False

def detect_hash_type(hash_file):
    print()
    print(colored("[#] Enhanced Hash Detection System (Not Guaranteed to work *SKIP if possible*)", Fore.CYAN))
    print("1) Auto-detect hash format (Multiple detection methods)")
    print("2) Skip detection and input format manually")
    print("3) Skip detection (use tool defaults)")
    
    while True:
        print()
        detection_choice = input(colored("Choose option [1/2/3]: ")).strip()
        if detection_choice in ['1', '2', '3']:
            break
        print(colored("[!] Invalid choice. Enter 1, 2, or 3.\n", Fore.RED))
    
    print()
    
    if detection_choice == '3':
        print(colored("[*] Skipping hash format detection. Using tool defaults.\n", Fore.YELLOW))
        return None, None
    
    elif detection_choice == '2':
        print(colored("[*] Manual format input:", Fore.CYAN))
        john_fmt = input(colored("Enter John format (e.g., raw-md5) or leave blank: ")).strip()
        hc_mode = input(colored("Enter Hashcat mode (e.g., 0 for MD5) or leave blank: ")).strip()
        print()
        return john_fmt if john_fmt else None, hc_mode if hc_mode else None
    
    else:
        # Enhanced auto-detection
        with open(hash_file, 'r') as f:
            content = f.readline().strip()
        
        print(colored("[*] Running multiple detection methods...", Fore.CYAN))
        
        # Method 1: Pattern-based detection
        pattern_results = advanced_hash_detection(content)
        print(colored(f"[*] Pattern detection found: {', '.join(pattern_results) if pattern_results else 'None'}", Fore.YELLOW))
        
        # Method 2: HashID detection
        hashid = HashID()
        hashid_results = list(hashid.identifyHash(content))
        print(colored(f"[*] HashID detected {len(hashid_results)} possible types", Fore.YELLOW))
        
        # Combine and prioritize results
        all_results = []
        
        # Add pattern results (higher priority)
        for hash_type in pattern_results:
            john_fmt, hc_mode = HASH_FORMATS.get(hash_type, (None, None))
            all_results.append({
                'name': hash_type,
                'source': 'Pattern',
                'confidence': 'High',
                'john_fmt': john_fmt,
                'hc_mode': hc_mode
            })
        
        # Add HashID results
        for h in hashid_results[:3]:  # Limit to top 3
            name = h['name']
            john_fmt, hc_mode = HASH_FORMATS.get(name, (None, None))
            # Avoid duplicates
            if not any(r['name'] == name for r in all_results):
                all_results.append({
                    'name': name,
                    'source': 'HashID',
                    'confidence': 'Medium',
                    'john_fmt': john_fmt,
                    'hc_mode': hc_mode
                })
        
        if all_results:
            print()
            print(colored("[*] Combined detection results:", Fore.CYAN))
            for idx, result in enumerate(all_results[:5], 1):
                confidence_color = Fore.GREEN if result['confidence'] == 'High' else Fore.YELLOW
                print(colored(f" {idx}. {result['name']} [{result['source']}] ({result['confidence']} confidence)", confidence_color))
                print(f"    John: {result['john_fmt'] or 'N/A'} | Hashcat: {result['hc_mode'] or 'N/A'}")
            
            # Hash validation
            if all_results:
                top_result = all_results[0]
                is_valid = validate_hash_format(content, top_result['name'])
                validation_msg = "✓ Valid" if is_valid else "⚠ Validation failed"
                print(colored(f"\n[*] Hash validation for {top_result['name']}: {validation_msg}", Fore.CYAN))

            while True:
                print()
                choice = input(colored("Choose format number, 'm' for manual input, or 's' to skip: ")).strip()
                if choice.lower() == 'm':
                    john_fmt = input(colored("Enter John format (leave blank if using Hashcat): ")).strip()
                    hc_mode = input(colored("Enter Hashcat mode (leave blank if using John): ")).strip()
                    print()
                    return john_fmt if john_fmt else None, hc_mode if hc_mode else None
                elif choice.lower() == 's':
                    print(colored("[*] Skipping format selection. Using tool defaults.\n", Fore.YELLOW))
                    return None, None
                elif choice.isdigit() and 1 <= int(choice) <= len(all_results):
                    selected = all_results[int(choice)-1]
                    john_fmt, hc_mode = selected['john_fmt'], selected['hc_mode']
                    if not john_fmt and not hc_mode:
                        print(colored("[!] No known John format or Hashcat mode for this hash type.\nPlease input manually.\n", Fore.RED))
                    else:
                        print(colored(f"[✔] Selected: {selected['name']} | John: {john_fmt} | Hashcat: {hc_mode}\n", Fore.GREEN))
                        return john_fmt, hc_mode
                else:
                    print(colored("[!] Invalid choice. Try again.\n", Fore.RED))
        else:
            print()
            print(colored("[!] Could not detect hash type with any method.", Fore.RED))
            john_fmt = input(colored("Enter John format (leave blank if using Hashcat): ")).strip()
            hc_mode = input(colored("Enter Hashcat mode (leave blank if using John): ")).strip()
            print()
            return john_fmt if john_fmt else None, hc_mode if hc_mode else None

def validate_john_format(fmt):
    try:
        output = subprocess.check_output(['john', '--list=formats'], text=True)
        return fmt in output
    except Exception:
        return False

def highlight_passwords(raw_output):
    print()
    print(f"{Fore.GREEN}{'='*15} Cracked Passwords {'='*15}{Style.RESET_ALL}\n")
    lines = raw_output.strip().split('\n')
    cracked_count = 0

    for line in lines:
        if ':' in line:
            parts = line.split(':')
            username = parts[0].strip()
            password = parts[1].strip()
            rest = parts[2:] if len(parts) > 2 else []

            if password in ['', '!', '*', '!!']:
                continue

            cracked_count += 1
            print(f"{Fore.YELLOW}{username}{Style.RESET_ALL}:{Fore.RED}{password}{Style.RESET_ALL}")
            if rest:
                print(f"    {':'.join(rest)}")
        else:
            print(line)

    if cracked_count == 0:
        print(colored("No passwords cracked.\n", Fore.RED))

    print(f"\n{Fore.GREEN}{'='*45}{Style.RESET_ALL}\n")

def get_cpu_threads():
    import multiprocessing
    max_threads = multiprocessing.cpu_count()
    print()
    print(colored(f"Your system has {max_threads} CPU threads available.\n", Fore.CYAN))
    while True:
        try:
            val = int(input(colored(f"How many CPU threads do you want to use for cracking? [1-{max_threads}]: ")))
            if 1 <= val <= max_threads:
                print()
                return val
        except Exception:
            pass
        print(colored("[!] Invalid input, please enter a number within the allowed range.\n", Fore.RED))

def crack_with_john(hash_file, wordlist, threads, john_fmt):
    if john_fmt and not validate_john_format(john_fmt):
        print(colored(f"[!] John does not support format '{john_fmt}'. Please try again with valid format.\n", Fore.RED))
        return

    print()
    print(colored("🔧 John the Ripper Attack Options:", Fore.CYAN))
    print("1) Wordlist attack only")
    print("2) Wordlist + Rules attack")
    print("3) Hybrid attack (wordlist + mask)")
    
    while True:
        attack_choice = input(colored("Choose attack type [1/2/3]: ")).strip()
        if attack_choice in ['1', '2', '3']:
            break
        print(colored("[!] Invalid choice. Enter 1, 2, or 3.\n", Fore.RED))
    
    base_cmd = ['john']
    fork_option = ['--fork=' + str(threads)] if threads > 1 else []
    format_option = [f'--format={john_fmt}'] if john_fmt else []
    
    if attack_choice == '2':
        # Rule-based attack
        print()
        print(colored("📋 Available Rule Files:", Fore.CYAN))
        available_rules = []
        for i, (name, path) in enumerate(JOHN_RULES.items(), 1):
            exists = "✓" if os.path.isfile(path) else "✗"
            print(f" {i}. {name} -> {path} [{exists}]")
            if os.path.isfile(path):
                available_rules.append((name, path))
        
        if available_rules:
            print(f" {len(available_rules)+1}. Use all available rules")
            print(f" {len(available_rules)+2}. Custom rule file")
            
            while True:
                try:
                    rule_choice = int(input(colored(f"Choose rule [1-{len(available_rules)+2}]: ")))
                    if 1 <= rule_choice <= len(available_rules):
                        rule_name, rule_path = available_rules[rule_choice - 1]
                        print(colored(f"[*] Using rule: {rule_name}", Fore.YELLOW))
                        rule_option = [f'--rules={rule_path}']
                        break
                    elif rule_choice == len(available_rules) + 1:
                        print(colored("[*] Using all available rules sequentially", Fore.YELLOW))
                        rule_option = ['--rules']
                        break
                    elif rule_choice == len(available_rules) + 2:
                        custom_rule = prompt_file("Enter path to custom rule file: ")
                        rule_option = [f'--rules={custom_rule}']
                        break
                except ValueError:
                    pass
                print(colored("[!] Invalid choice. Try again.\n", Fore.RED))
        else:
            print(colored("[!] No rule files found, using default rules.", Fore.YELLOW))
            rule_option = ['--rules']
        
        cmd = base_cmd + ['--wordlist=' + wordlist] + rule_option + format_option + fork_option + [hash_file]
    
    elif attack_choice == '3':
        # Hybrid attack
        print()
        mask = input(colored("Enter mask pattern (e.g., ?d?d?d for 3 digits): ")).strip()
        if mask:
            print(colored(f"[*] Using hybrid attack: wordlist + mask '{mask}'", Fore.YELLOW))
            cmd = base_cmd + ['--wordlist=' + wordlist, f'--mask={mask}'] + format_option + fork_option + [hash_file]
        else:
            print(colored("[!] No mask provided, falling back to wordlist attack.", Fore.YELLOW))
            cmd = base_cmd + ['--wordlist=' + wordlist] + format_option + fork_option + [hash_file]
    
    else:
        # Standard wordlist attack
        cmd = base_cmd + ['--wordlist=' + wordlist] + format_option + fork_option + [hash_file]

    print()
    print(colored("[*] Starting John the Ripper attack (resume supported)...", Fore.CYAN))
    print(colored(f"[*] Command: {' '.join(cmd)}", Fore.YELLOW))
    
    try:
        subprocess.run(cmd, check=True)
        output = subprocess.check_output(['john', '--show'] + format_option + [hash_file])
        print(colored("\n[+] Cracked Password(s):", Fore.GREEN))
        highlight_passwords(output.decode())
        save_cracked_result(hash_file, output.decode())
    except subprocess.CalledProcessError as e:
        print()
        print(colored(f"[!] John failed: {e}\n", Fore.RED))

def crack_with_hashcat(hash_file, wordlist, hc_mode, threads):
    if not hc_mode:
        print(colored("[!] Hashcat mode not provided. Cannot crack with Hashcat.\n", Fore.RED))
        return
    print()
    print(colored("[*] Starting cracking with Hashcat (resume supported)...\n", Fore.CYAN))

    if threads <= 2:
        workload = '1'
    elif threads <= 4:
        workload = '2'
    elif threads <= 8:
        workload = '3'
    else:
        workload = '4'

    try:
        subprocess.run([
            'hashcat', '-a', '0', '-m', hc_mode, hash_file, wordlist,
            '-w', workload, '--force',
        ], check=True)
        output = subprocess.check_output(['hashcat', '-m', hc_mode, '--show', hash_file])
        print(colored("\n[+] Cracked Password(s):", Fore.GREEN))
        highlight_passwords(output.decode())
        save_cracked_result(hash_file, output.decode())
    except subprocess.CalledProcessError as e:
        print()
        print(colored(f"[!] Hashcat failed: {e}\n", Fore.RED))

def save_cracked_result(source, data):
    with open("cracked_results.txt", "a") as f:
        f.write(f"\n[✔] From: {source}\n{data}\n")
    logging.info(f"Cracked result saved from {source}")

def shadow_unshadow():
    print()
    print(colored("🛠️ Prepare unshadow combined file for cracking\n", Fore.CYAN))
    shadow_file = prompt_file("Enter path to /etc/shadow (e.g. shadow.txt): ")
    passwd_file = prompt_file("Enter path to /etc/passwd (e.g. passwd.txt): ")
    output_file = prompt_nonempty("Enter output filename for combined hash (e.g. full.txt): ")

    try:
        result = subprocess.check_output(['unshadow', passwd_file, shadow_file])
        with open(output_file, 'w') as f:
            f.write(result.decode())
        print(colored(f"[✔] Combined shadow+passwd saved to: {output_file}\n", Fore.GREEN))
        return output_file
    except Exception as e:
        print()
        print(colored(f"[!] Unshadow failed: {e}\n", Fore.RED))
        return None

def extract_hash_from_shadow():
    print()
    shadow_file = prompt_file("Enter path to /etc/shadow (e.g. shadow.txt): ")
    output_file = prompt_nonempty("Enter output filename for extracted hash (e.g. shadow_only.txt): ")
    try:
        with open(shadow_file, 'r') as sf, open(output_file, 'w') as out:
            for line in sf:
                if line.strip() == '':
                    continue
                parts = line.strip().split(':')
                if len(parts) > 1 and parts[1] not in ['*', '!', '!!']:
                    out.write(f"{parts[0]}:{parts[1]}:\n")
        print(colored(f"[✔] Extracted hashes saved to: {output_file}\n", Fore.GREEN))
        return output_file
    except Exception as e:
        print()
        print(colored(f"[!] Failed to extract hashes from shadow file: {e}\n", Fore.RED))
        return None

def choose_wordlist(detected_hash_type=None):
    print()
    print(colored("📚 Smart Wordlist Selection:", Fore.CYAN))
    
    # Show smart recommendations if hash type is known
    if detected_hash_type:
        recommended = get_smart_wordlist_recommendations(detected_hash_type)
        print(colored(f"💡 Recommended for {detected_hash_type}: {', '.join(recommended)}", Fore.GREEN))
        print()
    
    print("Available options:")
    print("1) Use individual wordlist")
    print("2) Merge multiple wordlists")
    print("3) Smart selection (recommended for detected hash type)")
    
    while True:
        print()
        wordlist_choice = input(colored("Choose option [1/2/3]: ")).strip()
        if wordlist_choice in ['1', '2', '3']:
            break
        print(colored("[!] Invalid choice. Enter 1, 2, or 3.\n", Fore.RED))
    
    if wordlist_choice == '3' and detected_hash_type:
        # Smart selection
        recommended = get_smart_wordlist_recommendations(detected_hash_type)
        wordlist_paths = []
        
        for rec in recommended:
            path = WORDLISTS.get(rec)
            if path and os.path.isfile(path):
                wordlist_paths.append(path)
        
        if len(wordlist_paths) > 1:
            merged_path = f"merged_wordlist_{detected_hash_type.lower().replace('-', '_')}.txt"
            return merge_wordlists(wordlist_paths, merged_path)
        elif len(wordlist_paths) == 1:
            print(colored(f"[✔] Using recommended wordlist: {wordlist_paths[0]}\n", Fore.GREEN))
            return wordlist_paths[0]
        else:
            print(colored("[!] No recommended wordlists found, falling back to manual selection.", Fore.RED))
            wordlist_choice = '1'
    
    if wordlist_choice == '2':
        # Merge multiple wordlists
        print(colored("Select wordlists to merge:", Fore.CYAN))
        for i, (name, path) in enumerate(WORDLISTS.items(), 1):
            exists = "✓" if os.path.isfile(path) else "✗"
            print(f" {i}. {name} -> {path} [{exists}]")
        
        print()
        selected_indices = input(colored("Enter wordlist numbers separated by commas (e.g., 1,2,3): ")).strip()
        
        try:
            indices = [int(x.strip()) for x in selected_indices.split(',')]
            wordlist_paths = []
            wordlist_items = list(WORDLISTS.items())
            
            for idx in indices:
                if 1 <= idx <= len(wordlist_items):
                    name, path = wordlist_items[idx - 1]
                    if os.path.isfile(path):
                        wordlist_paths.append(path)
                        print(colored(f"[✔] Added: {name}", Fore.GREEN))
                    else:
                        print(colored(f"[!] File not found: {name}", Fore.RED))
            
            if wordlist_paths:
                merged_path = "merged_custom_wordlist.txt"
                return merge_wordlists(wordlist_paths, merged_path)
            else:
                print(colored("[!] No valid wordlists selected, falling back to manual selection.", Fore.RED))
                wordlist_choice = '1'
        except ValueError:
            print(colored("[!] Invalid input format, falling back to manual selection.", Fore.RED))
            wordlist_choice = '1'
    
    if wordlist_choice == '1':
        # Individual wordlist selection
        print()
        print(colored("📚 Available Wordlists:", Fore.CYAN))
        for i, (name, path) in enumerate(WORDLISTS.items(), 1):
            exists = "✓" if os.path.isfile(path) else "✗"
            print(f" {i}. {name} -> {path} [{exists}]")
        print(f" {len(WORDLISTS)+1}. Custom path")

        while True:
            try:
                print()
                choice = int(input(colored("Choose wordlist [1-{}]: ".format(len(WORDLISTS)+1))))
                if 1 <= choice <= len(WORDLISTS):
                    selected = list(WORDLISTS.values())[choice - 1]
                    if os.path.isfile(selected):
                        print(colored(f"[✔] Selected wordlist: {selected}\n", Fore.GREEN))
                        return selected
                    else:
                        print(colored("[!] Selected wordlist file does not exist.\n", Fore.RED))
                elif choice == len(WORDLISTS)+1:
                    path = prompt_file("Enter full path to custom wordlist: ")
                    return path
            except Exception:
                pass
            print(colored("[!] Invalid choice. Try again.\n", Fore.RED))

def main():
    print()
    print(colored("🔓 Hash Cracker | Supports ZIP/PDF/7z/Office + John/Hashcat + Shadow Cracking\n", Fore.YELLOW))

    print("Choose mode:")
    print("1) Crack from archive/file (extract hash)")
    print("2) Crack from /etc/shadow")
    print("3) Crack directly from a hash file")
    print("4) View supported file formats\n")

    mode = ''
    while mode not in ['1', '2', '3', '4']:
        mode = input(colored("Choose option [1/2/3/4]: ")).strip()
        print()
        if mode not in ['1', '2', '3', '4']:
            print(colored("[!] Invalid choice. Enter 1, 2, 3, or 4.\n", Fore.RED))
    
    if mode == '4':
        display_supported_formats()
        print(colored("Returning to main menu...\n", Fore.CYAN))
        return main()  # Return to main menu after showing formats
    
    if mode == '2':
        print(colored("Shadow cracking options:\n1) Use shadow + passwd files (unshadow)\n2) Extract hashes from shadow file only\n", Fore.CYAN))
        shadow_mode = ''
        while shadow_mode not in ['1', '2']:
            shadow_mode = input(colored("Choose option [1/2]: ")).strip()
            print()
            if shadow_mode not in ['1', '2']:
                print(colored("[!] Invalid choice. Enter 1 or 2.\n", Fore.RED))

        if shadow_mode == '1':
            hash_output = shadow_unshadow()
            if not hash_output:
                print(colored("[!] Could not prepare combined shadow file. Exiting.\n", Fore.RED))
                sys.exit(1)
        else:
            hash_output = extract_hash_from_shadow()
            if not hash_output:
                print(colored("[!] Could not extract hashes from shadow. Exiting.\n", Fore.RED))
                sys.exit(1)
    elif mode == '1':
        file_path = prompt_file("Enter path to target file (e.g., secret.zip): ")
        hash_output = prompt_nonempty("Enter output filename for hash (e.g., zip.hash): ")
        if not extract_hash(file_path, hash_output):
            print(colored("[!] Hash extraction failed. Exiting.\n", Fore.RED))
            sys.exit(1)
    else:
        # mode == 3, direct hash file input
        hash_output = prompt_file("Enter path to hash file (e.g., hashes.txt): ")

    tool = ''
    while tool not in ['john', 'hashcat']:
        tool = input(colored("Choose cracking tool (john/hashcat): ")).strip().lower()
        print()
        if tool not in ['john', 'hashcat']:
            print(colored("[!] Invalid input. Choose 'john' or 'hashcat'.\n", Fore.RED))

    john_fmt, hc_mode = detect_hash_type(hash_output)
    
    # Extract detected hash type for smart wordlist selection
    detected_type = None
    if john_fmt:
        # Map john format back to hash type
        for hash_type, (j_fmt, h_mode) in HASH_FORMATS.items():
            if j_fmt == john_fmt:
                detected_type = hash_type
                break
    
    wordlist = choose_wordlist(detected_type)
    threads = get_cpu_threads()

    if tool == 'john':
        crack_with_john(hash_output, wordlist, threads, john_fmt)
    else:
        crack_with_hashcat(hash_output, wordlist, hc_mode, threads)

    print(colored("🎉 Done. Check cracked_results.txt for saved output.\n", Fore.MAGENTA))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Interrupted by user. Exiting...\n", Fore.RED))
        sys.exit(0)

#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import logging
from colorama import Fore, Style, init
from hashid import HashID

init(autoreset=True)
logging.basicConfig(filename='crack.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TOOL_MAP = {
    'zip': 'zip2john',
    '7z': '7z2john.pl',
    'rar': 'rar2john',
    'pdf': 'pdf2john.pl',
    'doc': 'office2john.py',
    'docx': 'office2john.py',
    'xls': 'office2john.py',
    'xlsx': 'office2john.py',
}

WORDLISTS = {
    'rockyou.txt': '/usr/share/wordlists/rockyou.txt',
    'unix_users.txt': '/usr/share/metasploit-framework/data/wordlists/unix_users.txt',
    'xato-net-10-million.txt': '/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt',
    'scraped-JWT-secrets.txt': '/usr/share/seclists/Passwords/scraped-JWT-secrets.txt',
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
        print(colored("[!] Unsupported file type. Supported: zip, 7z, rar, pdf, doc, docx, xls, xlsx\n", Fore.RED))
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
    print(colored("[?] Hash format detection options:", Fore.CYAN))
    print("1) Auto-detect hash format")
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
        # Skip detection entirely, return None for both formats
        print(colored("[*] Skipping hash format detection. Using tool defaults.\n", Fore.YELLOW))
        return None, None
    
    elif detection_choice == '2':
        # Manual input only
        print(colored("[*] Manual format input:", Fore.CYAN))
        john_fmt = input(colored("Enter John format (e.g., raw-md5) or leave blank: ")).strip()
        hc_mode = input(colored("Enter Hashcat mode (e.g., 0 for MD5) or leave blank: ")).strip()
        print()
        return john_fmt if john_fmt else None, hc_mode if hc_mode else None
    
    else:
        # Auto-detection (option 1)
        with open(hash_file, 'r') as f:
            content = f.readline().strip()
        hashid = HashID()
        results = list(hashid.identifyHash(content))
        
        if results:
            print()
            print(colored("[*] Possible hash types detected:", Fore.CYAN))
            for idx, h in enumerate(results[:5], 1):
                name = h['name']
                john_fmt, hc_mode = HASH_FORMATS.get(name, (None, None))
                print(colored(f" {idx}. {name} | John format: {john_fmt or 'N/A'} | Hashcat mode: {hc_mode or 'N/A'}", Fore.YELLOW))

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
                elif choice.isdigit() and 1 <= int(choice) <= len(results[:5]):
                    name = results[int(choice)-1]['name']
                    john_fmt, hc_mode = HASH_FORMATS.get(name, (None, None))
                    if not john_fmt and not hc_mode:
                        print(colored("[!] No known John format or Hashcat mode for this hash type.\nPlease input manually.\n", Fore.RED))
                    else:
                        print(colored(f"[✔] Selected John format: {john_fmt}, Hashcat mode: {hc_mode}\n", Fore.GREEN))
                        return john_fmt, hc_mode
                else:
                    print(colored("[!] Invalid choice. Try again.\n", Fore.RED))
        else:
            print()
            print(colored("[!] Could not detect hash type.", Fore.RED))
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
    print(colored("[*] Starting cracking with John (resume supported)...\n", Fore.CYAN))
    try:
        fork_option = ['--fork=' + str(threads)] if threads > 1 else []
        format_option = [f'--format={john_fmt}'] if john_fmt else []
        subprocess.run(['john', '--wordlist=' + wordlist] + format_option + fork_option + [hash_file], check=True)
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

def choose_wordlist():
    print()
    print(colored("📚 Available Wordlists:", Fore.CYAN))
    for i, (name, path) in enumerate(WORDLISTS.items(), 1):
        print(f" {i}. {name} -> {path}")
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
    print("3) Crack directly from a hash file\n")

    mode = ''
    while mode not in ['1', '2', '3']:
        mode = input(colored("Choose option [1/2/3]: ")).strip()
        print()
        if mode not in ['1', '2', '3']:
            print(colored("[!] Invalid choice. Enter 1, 2 or 3.\n", Fore.RED))
    
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

    wordlist = choose_wordlist()
    threads = get_cpu_threads()

    john_fmt, hc_mode = detect_hash_type(hash_output)

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

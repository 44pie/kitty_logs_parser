#!/usr/bin/env python3
"""
Kitty Logs Parser - InfoStealer Log Analyzer
Supports various formats: Redline, Raccoon, Vidar, Mars, etc.
"""

import argparse
import csv
import sqlite3
import sys
import os
import re
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple
from collections import defaultdict

# Windows ANSI color support
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass

# ANSI Colors
PINK = "\033[38;5;213m"
WHITE = "\033[97m"
GRAY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""{PINK}
⠀⠀⠀⢠⡾⠲⠶⣤⣀⣠⣤⣤⣤⡿⠛⠿⡴⠾⠛⢻⡆⠀⠀⠀
⠀⠀⠀⣼⠁⠀⠀⠀⠉⠁⠀⢀⣿⠐⡿⣿⠿⣶⣤⣤⣷⡀⠀⠀
⠀⠀⠀⢹⡶⠀⠀⠀⠀⠀⠀⠌⢯⣡⣿⣿⣀⣸⣿⣦⢓⡟⠀⠀
⠀⠀⢀⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠹⣍⣭⣾⠁⠀⠀
⠀⣀⣸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣸⣷⣤⡀
⠈⠉⠹⣏⡁⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣸⣇⣀⠀
⠀⠐⠋⢻⣅⣄⢀⣀⣀⡀⠀⠯⠽⠀⢀⣀⣀⡀⠀⣤⣿⠀⠉⠀
⠀⠀⠴⠛⠙⣳⠋⠉⠉⠙⣆⠀⠀⢰⡟⠉⠈⠙⢷⠟⠉⠙⠂⠀
⠀⠀⠀⠀⠀⢻⣄⣠⣤⣴⠟⠛⠛⠛⢧⣤⣤⣀⡾⠀⠀⠀⠀⠀

{WHITE}KITTY LOGS PARSER{RESET}
{GRAY}InfoStealer Log Analyzer v1.0{RESET}
"""


@dataclass
class Credential:
    """Credential data"""
    host: str = ""
    login: str = ""
    password: str = ""
    soft: str = ""


@dataclass
class SystemInfo:
    """System information"""
    country: str = ""
    date: str = ""
    windows: str = ""
    computer_name: str = ""
    user_name: str = ""
    antivirus: str = ""
    processor: str = ""
    ram: str = ""
    videocard: str = ""
    resolution: str = ""
    ip: str = ""
    hwid: str = ""


@dataclass
class ParsedLog:
    """Parsed log data"""
    folder_name: str
    folder_path: str
    system_info: SystemInfo
    credentials: List[Credential] = field(default_factory=list)
    cookies_count: int = 0
    
    @property
    def passwords_count(self) -> int:
        return len(self.credentials)


def extract_domain(url: str) -> str:
    """Extract second-level domain"""
    if not url:
        return ""
    url = url.lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    url = url.split('/')[0].split(':')[0].split('?')[0]
    
    parts = url.split('.')
    if len(parts) >= 2:
        tlds = ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'me', 'ru', 'uk', 'de', 'fr', 'jp', 'br', 'au', 'in', 'it', 'es', 'nl', 'pl', 'ca', 'ch', 'at', 'be', 'se', 'no', 'dk', 'fi', 'pt', 'cz', 'hu', 'ro', 'bg', 'sk', 'ua', 'by', 'kz', 'ae', 'sa', 'eg', 'za', 'ng', 'ke', 'mx', 'ar', 'cl', 'pe', 'co', 've', 'ec', 'uy', 'py', 'bo', 'cr', 'pa', 'do', 'gt', 'hn', 'sv', 'ni', 'cu', 'jm', 'tt', 'bb', 'bs', 'pr', 'sg', 'my', 'th', 'vn', 'id', 'ph', 'tw', 'hk', 'kr', 'cn', 'nz', 'pk', 'bd', 'lk', 'np', 'mm', 'kh', 'la', 'bn', 'tr', 'il', 'ir', 'iq', 'sy', 'lb', 'jo', 'kw', 'qa', 'bh', 'om', 'ye', 'af', 'uz', 'tm', 'tj', 'kg', 'az', 'ge', 'am', 'gr', 'cy', 'mt', 'is', 'ie', 'lu', 'li', 'mc', 'sm', 'va', 'ad', 'ee', 'lv', 'lt', 'si', 'hr', 'ba', 'rs', 'me', 'mk', 'al', 'md', 'info', 'biz', 'xyz', 'online', 'site', 'app', 'dev', 'ai', 'tv', 'cc', 'ws', 'mobi', 'name', 'pro', 'asia', 'eu', 'club', 'shop', 'store', 'tech', 'blog', 'live', 'space', 'website', 'cloud', 'pw']
        if parts[-1] in tlds:
            return '.'.join(parts[-2:])
        elif len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']:
            return '.'.join(parts[-3:])
    return url


def extract_email(text: str) -> Optional[str]:
    """Extract email from text"""
    if not text:
        return None
    match = re.search(r'[\w\.\-\+]+@[\w\.\-]+\.[a-zA-Z]{2,}', text)
    return match.group(0).lower() if match else None


def is_email(text: str) -> bool:
    """Check if string is email"""
    if not text:
        return False
    return bool(re.match(r'^[\w\.\-\+]+@[\w\.\-]+\.[a-zA-Z]{2,}$', text.strip()))


def parse_passwords_file(content: str, soft_name: str = "") -> List[Credential]:
    """Parse passwords file (universal)"""
    credentials = []
    lines = content.split('\n')
    
    current_soft = soft_name
    current_host = ""
    current_login = ""
    current_password = ""
    in_block = False
    
    for line in lines:
        line_stripped = line.strip()
        line_lower = line_stripped.lower()
        
        if line_stripped.startswith('=') or line_stripped.startswith('-') * 5:
            continue
        
        if '===============' in line or '---------------' in line:
            if in_block and (current_login or current_password):
                credentials.append(Credential(
                    host=current_host,
                    login=current_login,
                    password=current_password,
                    soft=current_soft
                ))
            current_host = ""
            current_login = ""
            current_password = ""
            in_block = True
            continue
        
        if line_lower.startswith('soft:') or line_lower.startswith('browser:') or line_lower.startswith('application:'):
            current_soft = line_stripped.split(':', 1)[1].strip() if ':' in line_stripped else ""
            continue
        
        if any(line_lower.startswith(p) for p in ['url:', 'host:', 'link:', 'site:', 'domain:']):
            if in_block and current_host and (current_login or current_password):
                credentials.append(Credential(
                    host=current_host,
                    login=current_login,
                    password=current_password,
                    soft=current_soft
                ))
                current_login = ""
                current_password = ""
            current_host = line_stripped.split(':', 1)[1].strip() if ':' in line_stripped else ""
            in_block = True
            continue
        
        if any(line_lower.startswith(p) for p in ['login:', 'username:', 'user:', 'email:', 'mail:', 'account:']):
            current_login = line_stripped.split(':', 1)[1].strip() if ':' in line_stripped else ""
            continue
        
        if any(line_lower.startswith(p) for p in ['password:', 'pass:', 'pwd:']):
            current_password = line_stripped.split(':', 1)[1].strip() if ':' in line_stripped else ""
            continue
        
        if '\t' in line_stripped or ' | ' in line_stripped:
            parts = re.split(r'\t+|\s*\|\s*', line_stripped)
            if len(parts) >= 3:
                credentials.append(Credential(
                    host=parts[0].strip(),
                    login=parts[1].strip(),
                    password=parts[2].strip(),
                    soft=current_soft
                ))
                continue
        
        if line_stripped.count(':') >= 2 and not line_lower.startswith(('http:', 'https:')):
            parts = line_stripped.split(':')
            if len(parts) >= 3 and '.' in parts[0]:
                credentials.append(Credential(
                    host=parts[0].strip(),
                    login=parts[1].strip(),
                    password=':'.join(parts[2:]).strip(),
                    soft=current_soft
                ))
                continue
    
    if in_block and (current_login or current_password):
        credentials.append(Credential(
            host=current_host,
            login=current_login,
            password=current_password,
            soft=current_soft
        ))
    
    return credentials


def parse_system_info(content: str) -> SystemInfo:
    """Parse system information (universal)"""
    info = SystemInfo()
    
    patterns = {
        'country': [r'country[:\s]+([A-Z]{2})', r'\[([A-Z]{2})\]', r'location[:\s]+.*?([A-Z]{2})'],
        'windows': [r'windows[:\s]+(.+?)(?:\n|$)', r'os[:\s]+(.+?)(?:\n|$)', r'system[:\s]+(.+?)(?:\n|$)'],
        'computer_name': [r'computer[:\s]+(.+?)(?:\n|$)', r'pc[:\s]+(.+?)(?:\n|$)', r'hostname[:\s]+(.+?)(?:\n|$)'],
        'user_name': [r'user(?:name)?[:\s]+(.+?)(?:\n|$)', r'current user[:\s]+(.+?)(?:\n|$)'],
        'ip': [r'ip[:\s]+(\d+\.\d+\.\d+\.\d+)', r'external ip[:\s]+(\d+\.\d+\.\d+\.\d+)'],
        'antivirus': [r'antivirus[:\s]+(.+?)(?:\n|$)', r'av[:\s]+(.+?)(?:\n|$)', r'defender[:\s]+(.+?)(?:\n|$)'],
        'processor': [r'(?:cpu|processor)[:\s]+(.+?)(?:\n|$)'],
        'ram': [r'ram[:\s]+(.+?)(?:\n|$)', r'memory[:\s]+(.+?)(?:\n|$)'],
        'videocard': [r'(?:gpu|video|graphics)[:\s]+(.+?)(?:\n|$)'],
        'resolution': [r'resolution[:\s]+(.+?)(?:\n|$)', r'screen[:\s]+(.+?)(?:\n|$)'],
        'hwid': [r'hwid[:\s]+(.+?)(?:\n|$)', r'machine id[:\s]+(.+?)(?:\n|$)'],
        'date': [r'date[:\s]+(.+?)(?:\n|$)', r'time[:\s]+(.+?)(?:\n|$)']
    }
    
    content_lower = content.lower()
    
    for field_name, field_patterns in patterns.items():
        for pattern in field_patterns:
            match = re.search(pattern, content_lower if field_name == 'country' else content, re.IGNORECASE)
            if match:
                setattr(info, field_name, match.group(1).strip())
                break
    
    return info


def find_log_folders(base_path: str) -> List[str]:
    """Find all log folders"""
    folders = []
    base = Path(base_path)
    
    if not base.exists():
        return folders
    
    for item in base.iterdir():
        if item.is_dir():
            has_passwords = any(
                (item / name).exists() 
                for name in ['passwords.txt', 'Passwords.txt', 'passwords', 'Passwords', 
                            'All Passwords.txt', 'all_passwords.txt', 'Passwords.csv']
            )
            has_info = any(
                (item / name).exists()
                for name in ['information.txt', 'Information.txt', 'info.txt', 'Info.txt',
                            'System.txt', 'system.txt', 'UserInformation.txt']
            )
            
            if has_passwords or has_info:
                folders.append(str(item))
            else:
                sub_folders = find_log_folders(str(item))
                folders.extend(sub_folders)
    
    return folders


def parse_log_folder(folder_path: str) -> Optional[ParsedLog]:
    """Parse log folder"""
    folder = Path(folder_path)
    
    if not folder.exists():
        return None
    
    credentials = []
    password_files = ['passwords.txt', 'Passwords.txt', 'passwords', 'Passwords',
                     'All Passwords.txt', 'all_passwords.txt', 'Passwords.csv',
                     'Browsers/passwords.txt', 'Browser/passwords.txt']
    
    for pf in password_files:
        pf_path = folder / pf
        if pf_path.exists():
            try:
                content = pf_path.read_text(encoding='utf-8', errors='ignore')
                credentials.extend(parse_passwords_file(content))
            except Exception:
                try:
                    content = pf_path.read_text(encoding='latin-1', errors='ignore')
                    credentials.extend(parse_passwords_file(content))
                except Exception:
                    pass
    
    system_info = SystemInfo()
    info_files = ['information.txt', 'Information.txt', 'info.txt', 'Info.txt',
                 'System.txt', 'system.txt', 'UserInformation.txt', 'System Info.txt']
    
    for inf in info_files:
        inf_path = folder / inf
        if inf_path.exists():
            try:
                content = inf_path.read_text(encoding='utf-8', errors='ignore')
                system_info = parse_system_info(content)
                break
            except Exception:
                try:
                    content = inf_path.read_text(encoding='latin-1', errors='ignore')
                    system_info = parse_system_info(content)
                    break
                except Exception:
                    pass
    
    if not system_info.country:
        folder_name = folder.name
        match = re.search(r'[-_]([A-Z]{2})[A-Z0-9]', folder_name)
        if match:
            system_info.country = match.group(1)
    
    cookies_count = 0
    cookies_files = ['cookies.txt', 'Cookies.txt', 'cookies.sqlite', 'Cookies.sqlite',
                    'Browsers/cookies.txt', 'Browser/cookies.txt']
    for cf in cookies_files:
        cf_path = folder / cf
        if cf_path.exists():
            try:
                cookies_count = sum(1 for _ in open(cf_path, 'rb')) - 1
            except Exception:
                pass
            break
    
    return ParsedLog(
        folder_name=folder.name,
        folder_path=str(folder),
        system_info=system_info,
        credentials=credentials,
        cookies_count=max(0, cookies_count)
    )


class ProgressBar:
    """Advanced progress bar with detailed stats"""
    def __init__(self, total: int, width: int = 40):
        self.total = total
        self.width = width
        self.current = 0
        self.start_time = time.time()
        self.passwords = 0
        self.emails = 0
        self.cookies = 0
        self.logs_ok = 0
        self.errors = 0
        self.countries = defaultdict(int)
        self.domains = set()
    
    def update(self, current: int, log: Optional[ParsedLog] = None):
        self.current = current
        
        if log:
            self.logs_ok += 1
            self.passwords += log.passwords_count
            self.cookies += log.cookies_count
            
            if log.system_info.country:
                self.countries[log.system_info.country] += 1
            
            for cred in log.credentials:
                email = extract_email(cred.login)
                if email:
                    self.emails += 1
                domain = extract_domain(cred.host)
                if domain:
                    self.domains.add(domain)
        
        filled = int(self.width * current / self.total) if self.total > 0 else 0
        bar = f"{PINK}{'█' * filled}{GRAY}{'░' * (self.width - filled)}{RESET}"
        
        elapsed = time.time() - self.start_time
        rate = current / elapsed if elapsed > 0 else 0
        eta = (self.total - current) / rate if rate > 0 else 0
        
        percent = 100 * current / self.total if self.total > 0 else 0
        
        # Progress bar line
        line0 = f"\r{WHITE}[{bar}{WHITE}] {PINK}{percent:5.1f}%{RESET} {GRAY}|{RESET} {WHITE}{current}/{self.total}{RESET} {GRAY}|{RESET} {WHITE}{rate:.1f}/s{RESET} {GRAY}|{RESET} ETA: {WHITE}{eta:.0f}s{RESET}"
        
        # Stats in columns (2 lines) with blank line after progress bar
        line1 = f"\n\n  {PINK}Passwords:{RESET} {WHITE}{self.passwords:>10,}{RESET}   {PINK}Emails:{RESET}  {WHITE}{self.emails:>10,}{RESET}"
        line2 = f"\n  {PINK}Domains:{RESET}   {WHITE}{len(self.domains):>10,}{RESET}   {PINK}Logs OK:{RESET} {WHITE}{self.logs_ok:>10,}{RESET}"
        
        # Move cursor up (3 lines)
        sys.stdout.write("\033[3A" if current > 1 else "")
        sys.stdout.write(line0 + line1 + line2 + "          ")
        sys.stdout.flush()
    
    def add_error(self):
        self.errors += 1
    
    def finish(self):
        print("\n")


def process_logs(
    input_path: str,
    workers: int = 20,
    country_filter: Optional[Set[str]] = None
) -> Tuple[List[ParsedLog], Dict]:
    """Process all logs"""
    print(f"{GRAY}Scanning for log folders in: {WHITE}{input_path}{RESET}")
    folders = find_log_folders(input_path)
    total = len(folders)
    print(f"{GRAY}Found folders: {WHITE}{total}{RESET}\n\n")
    
    if not folders:
        return [], {}
    
    results = []
    stats = defaultdict(int)
    stats['total_folders'] = total
    
    progress = ProgressBar(total)
    processed = 0
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(parse_log_folder, f): f for f in folders}
        
        for future in as_completed(futures):
            processed += 1
            
            try:
                result = future.result()
                if result:
                    if country_filter:
                        if result.system_info.country.upper() not in country_filter:
                            progress.update(processed)
                            continue
                    
                    results.append(result)
                    stats['logs_parsed'] += 1
                    stats['total_passwords'] += result.passwords_count
                    stats['total_cookies'] += result.cookies_count
                    
                    if result.system_info.country:
                        stats[f'country_{result.system_info.country}'] += 1
                    
                    progress.update(processed, result)
                else:
                    progress.update(processed)
            except Exception:
                stats['errors'] += 1
                progress.add_error()
                progress.update(processed)
    
    progress.finish()
    return results, dict(stats)


def get_available_countries(logs: List[ParsedLog]) -> Dict[str, int]:
    """Get available countries list"""
    countries = defaultdict(int)
    for log in logs:
        if log.system_info.country:
            countries[log.system_info.country.upper()] += 1
    return dict(sorted(countries.items(), key=lambda x: -x[1]))


def matches_search(cred: Credential, search_query: Optional[str]) -> bool:
    """Check if credential matches search query"""
    if not search_query:
        return True
    query_lower = search_query.lower()
    searchable = f"{cred.host} {cred.login} {cred.password}".lower()
    return query_lower in searchable


def matches_domain_filter(domain: str, domain_filter: Set[str]) -> bool:
    """Check if domain matches any filter pattern"""
    domain_lower = domain.lower()
    if domain_lower in domain_filter:
        return True
    parts = domain_lower.split('.')
    if len(parts) >= 2:
        base = parts[0]
        if any(base == f.split('.')[0] for f in domain_filter):
            return True
    return False


def export_domains(logs: List[ParsedLog], output_file: str, search_filter: Optional[str] = None, domain_filter: Optional[Set[str]] = None):
    """Export unique domains to TXT"""
    domains = set()
    for log in logs:
        for cred in log.credentials:
            if not matches_search(cred, search_filter):
                continue
            domain = extract_domain(cred.host)
            if domain and '.' in domain:
                if domain_filter and matches_domain_filter(domain, domain_filter):
                    continue
                domains.add(domain)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for domain in sorted(domains):
            f.write(f"{domain}\n")
    
    return len(domains)


def export_passwords(logs: List[ParsedLog], output_file: str, search_filter: Optional[str] = None):
    """Export unique passwords to TXT"""
    passwords = set()
    for log in logs:
        for cred in log.credentials:
            if not matches_search(cred, search_filter):
                continue
            if cred.password and cred.password.strip():
                passwords.add(cred.password)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for pwd in sorted(passwords):
            f.write(f"{pwd}\n")
    
    return len(passwords)


def export_emails(logs: List[ParsedLog], output_file: str, search_filter: Optional[str] = None):
    """Export unique emails to TXT"""
    emails = set()
    for log in logs:
        for cred in log.credentials:
            if not matches_search(cred, search_filter):
                continue
            email = extract_email(cred.login)
            if email:
                emails.add(email)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for email in sorted(emails):
            f.write(f"{email}\n")
    
    return len(emails)


def export_email_pass(logs: List[ParsedLog], output_file: str, search_filter: Optional[str] = None):
    """Export email:password pairs to TXT"""
    pairs = set()
    for log in logs:
        for cred in log.credentials:
            if not matches_search(cred, search_filter):
                continue
            email = extract_email(cred.login)
            if email and cred.password:
                pairs.add(f"{email}:{cred.password}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for pair in sorted(pairs):
            f.write(f"{pair}\n")
    
    return len(pairs)


def export_logins(logs: List[ParsedLog], output_file: str, search_filter: Optional[str] = None):
    """Export unique logins to TXT"""
    logins = set()
    for log in logs:
        for cred in log.credentials:
            if not matches_search(cred, search_filter):
                continue
            if cred.login and cred.login.strip():
                logins.add(cred.login)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for login in sorted(logins):
            f.write(f"{login}\n")
    
    return len(logins)


def export_login_pass(logs: List[ParsedLog], output_file: str, search_filter: Optional[str] = None):
    """Export login:password pairs to TXT"""
    pairs = set()
    for log in logs:
        for cred in log.credentials:
            if not matches_search(cred, search_filter):
                continue
            if cred.login and cred.password:
                pairs.add(f"{cred.login}:{cred.password}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for pair in sorted(pairs):
            f.write(f"{pair}\n")
    
    return len(pairs)


def search_logs(logs: List[ParsedLog], query: str, output_file: str):
    """Search logs by keyword and save detailed results"""
    query_lower = query.lower()
    results = []
    
    for log in logs:
        for cred in log.credentials:
            searchable = f"{cred.host} {cred.login} {cred.password}".lower()
            if query_lower in searchable:
                results.append({
                    'url': cred.host,
                    'login': cred.login,
                    'password': cred.password,
                    'log_path': log.folder_path,
                    'country': log.system_info.country
                })
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for i, r in enumerate(results, 1):
            f.write(f"[{i}] ============================\n")
            f.write(f"URL:      {r['url']}\n")
            f.write(f"Login:    {r['login']}\n")
            f.write(f"Password: {r['password']}\n")
            f.write(f"Country:  {r['country']}\n")
            f.write(f"Log:      {r['log_path']}\n")
            f.write("\n")
    
    return len(results)


def export_csv(logs: List[ParsedLog], output_file: str, search_filter: Optional[str] = None):
    """Export to CSV"""
    fieldnames = ['domain', 'url', 'login', 'password', 'browser', 'country', 
                 'windows', 'computer', 'ip', 'log_folder']
    
    count = 0
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for log in logs:
            info = log.system_info
            for cred in log.credentials:
                if not matches_search(cred, search_filter):
                    continue
                writer.writerow({
                    'domain': extract_domain(cred.host),
                    'url': cred.host,
                    'login': cred.login,
                    'password': cred.password,
                    'browser': cred.soft,
                    'country': info.country,
                    'windows': info.windows,
                    'computer': info.computer_name,
                    'ip': info.ip,
                    'log_folder': log.folder_name
                })
                count += 1
    
    return count


def export_sqlite(logs: List[ParsedLog], db_path: str, search_filter: Optional[str] = None):
    """Export to SQLite database (appends to existing data)"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        url TEXT,
        login TEXT,
        password TEXT,
        browser TEXT,
        country TEXT,
        windows TEXT,
        computer TEXT,
        ip TEXT,
        log_folder TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_domain ON credentials(domain)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_login ON credentials(login)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_country ON credentials(country)''')
    
    count = 0
    for log in logs:
        info = log.system_info
        for cred in log.credentials:
            if not matches_search(cred, search_filter):
                continue
            cursor.execute('''INSERT INTO credentials 
                (domain, url, login, password, browser, country, windows, computer, ip, log_folder)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (extract_domain(cred.host), cred.host, cred.login, cred.password,
                 cred.soft, info.country, info.windows, info.computer_name,
                 info.ip, log.folder_name))
            count += 1
    
    conn.commit()
    
    cursor.execute('SELECT COUNT(*) FROM credentials')
    total = cursor.fetchone()[0]
    
    conn.close()
    return count, total


def print_stats(stats: Dict, logs: List[ParsedLog], search_filter: Optional[str] = None, domain_filter: Optional[Set[str]] = None):
    """Print statistics with filters applied"""
    print(f"{PINK}{'─' * 50}{RESET}")
    print(f"{PINK}STATISTICS{RESET}")
    print(f"{PINK}{'─' * 50}{RESET}")
    
    print(f"{WHITE}Folders processed:   {GRAY}{stats.get('total_folders', 0):,}{RESET}")
    print(f"{WHITE}Logs parsed:         {GRAY}{stats.get('logs_parsed', 0):,}{RESET}")
    print(f"{WHITE}Total passwords:     {GRAY}{stats.get('total_passwords', 0):,}{RESET}")
    
    unique_domains = set()
    unique_emails = set()
    unique_passwords = set()
    unique_logins = set()
    
    for log in logs:
        for cred in log.credentials:
            # Domain filter only affects domains, not other data
            domain = extract_domain(cred.host)
            if domain:
                if not (domain_filter and matches_domain_filter(domain, domain_filter)):
                    unique_domains.add(domain)
            
            # Search filter affects all data
            if search_filter and not matches_search(cred, search_filter):
                continue
            
            email = extract_email(cred.login)
            if email:
                unique_emails.add(email)
            if cred.password:
                unique_passwords.add(cred.password)
            if cred.login:
                unique_logins.add(cred.login)
    
    print(f"{WHITE}Unique domains:      {GRAY}{len(unique_domains):,}{RESET}")
    print(f"{WHITE}Unique emails:       {GRAY}{len(unique_emails):,}{RESET}")
    print(f"{WHITE}Unique logins:       {GRAY}{len(unique_logins):,}{RESET}")
    print(f"{WHITE}Unique passwords:    {GRAY}{len(unique_passwords):,}{RESET}")
    
    countries = get_available_countries(logs)
    if countries:
        print(f"\n{PINK}{'─' * 50}{RESET}")
        print(f"{PINK}Top 10 Countries:{RESET}")
        print(f"{PINK}{'─' * 50}{RESET}")
        for country, count in list(countries.items())[:10]:
            print(f"  {WHITE}{country}: {GRAY}{count:,}{RESET}")


def main():
    print(BANNER)
    script_dir = Path(__file__).parent
    
    parser = argparse.ArgumentParser(
        description=f'{PINK}Kitty Logs Parser{RESET} - InfoStealer Log Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{PINK}Usage Examples:{RESET}
  {WHITE}python kitty_logs_parser.py -i ./logs -o ./results -d{RESET}
  {GRAY}   Export all unique domains{RESET}
  
  {WHITE}python kitty_logs_parser.py -i ./logs -o ./results -c RU,UA,BY{RESET}
  {GRAY}   Filter by countries{RESET}
  
  {WHITE}python kitty_logs_parser.py -i ./logs -o ./results -a --csv{RESET}
  {GRAY}   Export everything + CSV table{RESET}
  
  {WHITE}python kitty_logs_parser.py -i ./logs -o ./results -s "paypal"{RESET}
  {GRAY}   Search by keyword{RESET}
        """
    )
    
    parser.add_argument('-i', '--input', required=True,
                       help='Input directory with logs')
    
    parser.add_argument('-o', '--output', default='./output',
                       help='Output directory for results (default: ./output)')
    
    parser.add_argument('-c', '--country', nargs='?', const='SHOW', default=None,
                       help='Filter by countries (comma-separated) or show available')
    
    parser.add_argument('-d', '--domains', action='store_true',
                       help='Export unique second-level domains')
    
    parser.add_argument('-p', '--passwords', action='store_true',
                       help='Export unique passwords')
    
    parser.add_argument('-e', '--emails', action='store_true',
                       help='Export unique emails')
    
    parser.add_argument('-ep', dest='email_pass', action='store_true',
                       help='Export email:password pairs')
    
    parser.add_argument('-l', '--logins', action='store_true',
                       help='Export unique logins')
    
    parser.add_argument('-lp', dest='login_pass', action='store_true',
                       help='Export login:password pairs')
    
    parser.add_argument('-s', '--search',
                       help='Search by keyword')
    
    parser.add_argument('-a', '--all', action='store_true',
                       help='Export all data types (domains, passwords, emails, logins, pairs)')
    
    parser.add_argument('--csv', action='store_true',
                       help='Export to CSV table')
    
    parser.add_argument('--sqlite', nargs='?', const='full_db.sqlite', default=None,
                       help='Export to SQLite database (default: full_db.sqlite)')
    
    parser.add_argument('-w', '--workers', type=int, default=20,
                       help='Number of threads (default: 20)')
    
    parser.add_argument('-f', '--filter', nargs='?', const='auto', default=None,
                       help='Filter file with domains to exclude (default: filter.txt in script dir)')
    
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"{PINK}Error:{RESET} {WHITE}Directory {args.input} not found{RESET}")
        sys.exit(1)
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"{PINK}Input directory:{RESET}  {WHITE}{args.input}{RESET}")
    print(f"{PINK}Output directory:{RESET} {WHITE}{args.output}{RESET}")
    print()
    
    country_filter = None
    if args.country and args.country != 'SHOW':
        country_filter = set(c.strip().upper() for c in args.country.split(','))
        print(f"{GRAY}Country filter: {WHITE}{', '.join(country_filter)}{RESET}\n")
    
    start_time = time.time()
    logs, stats = process_logs(args.input, args.workers, country_filter)
    elapsed = time.time() - start_time
    
    if not logs:
        print(f"{PINK}No logs found for processing{RESET}")
        sys.exit(1)
    
    if args.country == 'SHOW':
        countries = get_available_countries(logs)
        print(f"\n{PINK}Available Countries:{RESET}")
        for country, count in countries.items():
            print(f"  {WHITE}{country}: {GRAY}{count:,} logs{RESET}")
        sys.exit(0)
    
    # Handle --all flag
    if args.all:
        args.domains = True
        args.passwords = True
        args.emails = True
        args.email_pass = True
        args.logins = True
        args.login_pass = True
    
    exported = []
    search_filter = args.search  # Use search as filter for all exports
    
    # Load domain filter
    domain_filter = set()
    if args.filter:
        if args.filter == 'auto':
            # Use provided path or default
            filter_path = script_dir / 'filter.txt'
        else:
            filter_path = Path(args.filter)
        
        if filter_path.exists():
            with open(filter_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        domain_filter.add(line)
            print(f"{PINK}Domain filter:{RESET} {WHITE}{len(domain_filter):,} domains excluded{RESET}")
        else:
            print(f"{PINK}Warning:{RESET} {WHITE}Filter file not found: {filter_path}{RESET}")
    
    # Show search filter info
    if search_filter:
        print(f"{PINK}Search filter:{RESET} {WHITE}{search_filter}{RESET}")
    
    if search_filter or domain_filter:
        print()
    
    if args.domains:
        suffix = f"_{search_filter}" if search_filter else ""
        file_path = output_dir / f'domains{suffix}.txt'
        count = export_domains(logs, str(file_path), search_filter, domain_filter if domain_filter else None)
        exported.append(f"Domains: {count:,} -> {file_path}")
    
    if args.passwords:
        suffix = f"_{search_filter}" if search_filter else ""
        file_path = output_dir / f'passwords{suffix}.txt'
        count = export_passwords(logs, str(file_path), search_filter)
        exported.append(f"Passwords: {count:,} -> {file_path}")
    
    if args.emails:
        suffix = f"_{search_filter}" if search_filter else ""
        file_path = output_dir / f'emails{suffix}.txt'
        count = export_emails(logs, str(file_path), search_filter)
        exported.append(f"Emails: {count:,} -> {file_path}")
    
    if args.email_pass:
        suffix = f"_{search_filter}" if search_filter else ""
        file_path = output_dir / f'email_pass{suffix}.txt'
        count = export_email_pass(logs, str(file_path), search_filter)
        exported.append(f"Email:Pass: {count:,} -> {file_path}")
    
    if args.logins:
        suffix = f"_{search_filter}" if search_filter else ""
        file_path = output_dir / f'logins{suffix}.txt'
        count = export_logins(logs, str(file_path), search_filter)
        exported.append(f"Logins: {count:,} -> {file_path}")
    
    if args.login_pass:
        suffix = f"_{search_filter}" if search_filter else ""
        file_path = output_dir / f'login_pass{suffix}.txt'
        count = export_login_pass(logs, str(file_path), search_filter)
        exported.append(f"Login:Pass: {count:,} -> {file_path}")
    
    # Always save detailed search results when -s is used
    if args.search:
        file_path = output_dir / f'search_{args.search}.txt'
        count = search_logs(logs, args.search, str(file_path))
        exported.append(f"Search '{args.search}': {count:,} -> {file_path}")
    
    if args.csv:
        suffix = f"_{search_filter}" if search_filter else ""
        file_path = output_dir / f'data{suffix}.csv'
        count = export_csv(logs, str(file_path), search_filter)
        exported.append(f"CSV: {count:,} rows -> {file_path}")
    
    if args.sqlite:
        # Use provided path or default
        db_path = Path(args.sqlite)
        added, total = export_sqlite(logs, str(db_path), search_filter)
        exported.append(f"SQLite: +{added:,} rows (total: {total:,}) -> {db_path}")
    
    print_stats(stats, logs, search_filter, domain_filter if domain_filter else None)
    
    print(f"\n{PINK}{'─' * 50}{RESET}")
    print(f"{PINK}EXPORT{RESET}")
    print(f"{PINK}{'─' * 50}{RESET}")
    
    if exported:
        for exp in exported:
            print(f"{WHITE}{exp}{RESET}")
    else:
        print(f"{GRAY}No export options specified. Use -d, -p, -e, -ep, -l, -lp, -s, -a, --csv, --sqlite{RESET}")
    
    print(f"\n{GRAY}Execution time: {WHITE}{elapsed:.1f}s{RESET}")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
domain_filter.py — рекурсивный сборщик доменов из CSV/TXT файлов
с фильтрацией по CMS и минимальному трафику.

Usage:
  python3 domain_filter.py -i ./dir --presta --min 5000 --out result.txt
  python3 domain_filter.py -i ./dir --cms Shopify --min 10000 --out result.txt
"""

import argparse
import csv
import os
import sys
from pathlib import Path

ANSI_GRAY  = "\033[90m"
ANSI_GREEN = "\033[92m"
ANSI_PINK  = "\033[38;5;213m"
ANSI_WHITE = "\033[97m"
ANSI_RESET = "\033[0m"


def parse_traffic(val: str) -> int:
    """Parse traffic value, return 0 if empty/invalid"""
    if not val:
        return 0
    try:
        return int(str(val).replace(',', '').replace(' ', '').strip())
    except (ValueError, TypeError):
        return 0


def max_traffic(*vals) -> int:
    """Return max traffic from multiple columns"""
    return max(parse_traffic(v) for v in vals)


def cms_matches(cms_val: str, cms_filter: str) -> bool:
    """Check if CMS column matches filter (case-insensitive substring)"""
    if not cms_filter:
        return True
    if not cms_val:
        return False
    return cms_filter.lower() in cms_val.lower()


def process_csv(filepath: Path, cms_filter: str, min_traffic: int) -> list:
    """Parse CSV file and return matching domains"""
    domains = []
    try:
        with open(filepath, encoding='utf-8', errors='ignore', newline='') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return []

            headers_lower = [h.lower().strip() for h in reader.fieldnames]

            # Find column indices
            def find_col(*names):
                for name in names:
                    for i, h in enumerate(headers_lower):
                        if name == h:
                            return reader.fieldnames[i]
                return None

            col_domain  = find_col('domain', 'domains', 'host', 'url', 'site')
            col_traffic1 = find_col('hypestat_monthly', 'hypestat', 'monthly_traffic', 'traffic')
            col_traffic2 = find_col('informer_monthly', 'informer', 'visits')
            col_cms     = find_col('cms', 'platform', 'technology')

            if not col_domain:
                return []

            for row in reader:
                domain = row.get(col_domain, '').strip().lower()
                if not domain or domain == 'domain':
                    continue

                # Traffic filter
                if min_traffic > 0:
                    t1 = parse_traffic(row.get(col_traffic1, '') if col_traffic1 else '')
                    t2 = parse_traffic(row.get(col_traffic2, '') if col_traffic2 else '')
                    traffic = max(t1, t2)
                    if traffic < min_traffic:
                        continue

                # CMS filter
                if cms_filter:
                    cms_val = row.get(col_cms, '') if col_cms else ''
                    if not cms_matches(cms_val, cms_filter):
                        continue

                domains.append(domain)

    except Exception as e:
        print(f"{ANSI_GRAY}  skip {filepath.name}: {e}{ANSI_RESET}", file=sys.stderr)

    return domains


def process_txt(filepath: Path, cms_filter: str, min_traffic: int) -> list:
    """Parse plain TXT domain list — only usable when no metadata filters applied"""
    if cms_filter or min_traffic > 0:
        return []
    domains = []
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith('#') or ' ' in line or ',' in line:
                    continue
                if '.' in line:
                    domains.append(line)
    except Exception:
        pass
    return domains


def collect_domains(input_dir: str, cms_filter: str, min_traffic: int) -> set:
    """Recursively scan directory for matching domains"""
    found = set()
    base = Path(input_dir)
    csv_files = txt_files = 0
    total_csv_domains = total_txt_domains = 0

    for root, dirs, files in os.walk(base):
        dirs.sort()
        for fname in sorted(files):
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()

            if ext == '.csv':
                csv_files += 1
                domains = process_csv(fpath, cms_filter, min_traffic)
                if domains:
                    print(f"{ANSI_GRAY}  {fpath.relative_to(base)}: {ANSI_GREEN}+{len(domains)}{ANSI_RESET}")
                    total_csv_domains += len(domains)
                    found.update(domains)

            elif ext in ('.txt', '.log', '') and not fname.startswith('.'):
                txt_files += 1
                domains = process_txt(fpath, cms_filter, min_traffic)
                if domains:
                    print(f"{ANSI_GRAY}  {fpath.relative_to(base)}: {ANSI_GREEN}+{len(domains)}{ANSI_RESET}")
                    total_txt_domains += len(domains)
                    found.update(domains)

    print(f"\n{ANSI_GRAY}Scanned: {csv_files} CSV, {txt_files} TXT{ANSI_RESET}")
    return found


def main():
    parser = argparse.ArgumentParser(
        description='Recursive domain collector with CMS and traffic filters'
    )
    parser.add_argument('-i', '--input', required=True, help='Input directory to scan')
    parser.add_argument('--out', required=True, help='Output file (plain domain list)')
    parser.add_argument('--presta', action='store_true', help='Filter PrestaShop only')
    parser.add_argument('--cms', default='', help='Filter by CMS name (e.g. Shopify, WordPress)')
    parser.add_argument('--min', type=int, default=0, dest='min_traffic',
                        help='Minimum monthly traffic (uses max of available traffic columns)')
    args = parser.parse_args()

    cms_filter = 'PrestaShop' if args.presta else args.cms

    print(f"{ANSI_PINK}Domain Filter{ANSI_RESET}")
    print(f"{ANSI_GRAY}Input:   {ANSI_WHITE}{args.input}{ANSI_RESET}")
    print(f"{ANSI_GRAY}CMS:     {ANSI_WHITE}{cms_filter or 'any'}{ANSI_RESET}")
    print(f"{ANSI_GRAY}Traffic: {ANSI_WHITE}>= {args.min_traffic:,}{ANSI_RESET}")
    print(f"{ANSI_GRAY}Output:  {ANSI_WHITE}{args.out}{ANSI_RESET}\n")

    if not Path(args.input).exists():
        print(f"ERROR: directory not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    domains = collect_domains(args.input, cms_filter, args.min_traffic)

    sorted_domains = sorted(domains)
    with open(args.out, 'w', encoding='utf-8') as f:
        for d in sorted_domains:
            f.write(d + '\n')

    print(f"\n{ANSI_GREEN}Done: {len(sorted_domains):,} unique domains → {args.out}{ANSI_RESET}")


if __name__ == '__main__':
    main()

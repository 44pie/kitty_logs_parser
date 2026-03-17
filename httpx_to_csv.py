#!/usr/bin/env python3
"""
httpx_to_csv.py — парсит JSONL вывод httpx и создаёт CSV
с CMS, сервером, CDN/WAF.

Usage:
  python3 httpx_to_csv.py -i results.jsonl -o report.csv
  python3 httpx_to_csv.py -i results.jsonl -o report.csv --filter-cms PrestaShop
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

CMS_LIST = {
    'prestashop':    'PrestaShop',
    'wordpress':     'WordPress',
    'woocommerce':   'WooCommerce',
    'shopify':       'Shopify',
    'magento':       'Magento',
    'drupal':        'Drupal',
    'joomla':        'Joomla',
    'opencart':      'OpenCart',
    'wix':           'Wix',
    'squarespace':   'Squarespace',
    'bigcommerce':   'BigCommerce',
    'typo3':         'TYPO3',
    'contao':        'Contao',
    'modx':          'MODX',
    'bitrix':        'Bitrix',
    'weebly':        'Weebly',
    'ghost':         'Ghost',
    'umbraco':       'Umbraco',
    'sitecore':      'Sitecore',
    'oscommerce':    'osCommerce',
    'zen cart':      'Zen Cart',
    'cubecart':      'CubeCart',
    'virtuemart':    'VirtueMart',
    'ecwid':         'Ecwid',
    'cs-cart':       'CS-Cart',
    'x-cart':        'X-Cart',
    'nopcommerce':   'nopCommerce',
    'spree':         'Spree',
    'sylius':        'Sylius',
    'laravel':       'Laravel',
    'symfony':       'Symfony',
    'codeigniter':   'CodeIgniter',
    'yii':           'Yii',
    'django':        'Django',
    'ruby on rails': 'Ruby on Rails',
}

SERVER_LIST = {
    'nginx', 'apache', 'litespeed', 'openresty', 'iis', 'caddy',
    'tomcat', 'gunicorn', 'uvicorn', 'cloudflare', 'cowboy',
    'pepyaka', 'squarespace', 'lighttpd', 'cherokee', 'jetty',
}

CDN_WAF_LIST = {
    'cloudflare', 'akamai', 'fastly', 'aws', 'cloudfront', 'imperva',
    'incapsula', 'sucuri', 'wordfence', 'mod_security', 'f5',
    'barracuda', 'fortinet', 'azure', 'google cloud', 'bunny cdn',
    'stackpath', 'keycdn', 'limelight', 'edgecast',
}

ANALYTICS_LIST = {
    'google analytics', 'google tag manager', 'gtm', 'facebook pixel',
    'hotjar', 'mixpanel', 'segment', 'amplitude', 'yandex metrika',
    'matomo', 'piwik', 'heap', 'fullstory', 'mouseflow', 'crazyegg',
    'clicky', 'statcounter', 'kissmetrics',
}

_INTERNAL_HOST_RE = re.compile(
    r'\.internal$|\.compute\.|^ip-\d|\.amazonaws\.com|'
    r'\.eu-west|\.us-east|\.ap-|\.local$',
    re.I,
)


def parse_webserver(ws: str) -> tuple:
    """Parse webserver field → (name, version).
    Returns ('', '') for internal/cloud hostnames."""
    if not ws:
        return ('', '')
    ws = ws.strip()
    if _INTERNAL_HOST_RE.search(ws):
        return ('', '')
    m = re.match(r'^([A-Za-z][A-Za-z0-9._-]*)/([0-9][0-9.\-]*)', ws)
    if m:
        name = m.group(1)
        version = m.group(2).rstrip('.')
        return (name, version)
    return (ws.split('/')[0].strip(), '')


def classify_tech(tech_list: list) -> dict:
    """Classify technology list into cms/server/cdn/analytics categories.
    Returns canonical names and versions (without version noise)."""
    result = {
        'cms':         '',
        'cms_version': '',
        'server':      '',
        'cdn_waf':     '',
    }

    for tech in tech_list:
        parts = tech.split(':', 1)
        raw_base = parts[0].strip()
        version   = parts[1].strip() if len(parts) > 1 else ''
        t_base    = raw_base.lower()

        for keyword, canonical in CMS_LIST.items():
            if keyword in t_base:
                if not result['cms']:
                    result['cms']         = canonical
                    result['cms_version'] = version
                break
        else:
            for srv in SERVER_LIST:
                if srv in t_base:
                    if not result['server']:
                        result['server'] = raw_base
                    break
            else:
                for cdn in CDN_WAF_LIST:
                    if cdn in t_base:
                        if not result['cdn_waf']:
                            result['cdn_waf'] = raw_base
                        break

    return result


def parse_jsonl(filepath: str, cms_filter: str) -> list:
    rows    = []
    skipped = 0
    total   = 0

    with open(filepath, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            tech_list  = d.get('tech') or []
            classified = classify_tech(tech_list)

            if cms_filter and cms_filter.lower() not in classified['cms'].lower():
                continue

            ws_name, ws_version = parse_webserver(d.get('webserver', ''))

            server         = ws_name or classified['server']
            server_version = ws_version

            cdn = d.get('cdn_name', '') or classified['cdn_waf']

            rows.append({
                'domain':         d.get('host', ''),
                'ip':             d.get('host_ip', ''),
                'status_code':    d.get('status_code', ''),
                'cms':            classified['cms'],
                'cms_version':    classified['cms_version'],
                'server':         server,
                'server_version': server_version,
                'cdn':            cdn,
                'title':          d.get('title', ''),
            })

    print(f"Обработано: {total} строк | Пропущено: {skipped} | Результат: {len(rows)}")
    return rows


def write_csv(rows: list, outfile: str):
    if not rows:
        print("Нет данных для записи")
        return

    fields = [
        'domain', 'ip', 'status_code',
        'cms', 'cms_version',
        'server', 'server_version',
        'cdn', 'title',
    ]

    with open(outfile, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV записан: {outfile} ({len(rows)} строк)")


def main():
    parser = argparse.ArgumentParser(description='httpx JSONL → CSV конвертер')
    parser.add_argument('-i', '--input',    required=True, help='Входной .jsonl файл')
    parser.add_argument('-o', '--output',   required=True, help='Выходной .csv файл')
    parser.add_argument('--filter-cms',     default='',   help='Фильтр по CMS (напр: PrestaShop)')
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Файл не найден: {args.input}", file=sys.stderr)
        sys.exit(1)

    rows = parse_jsonl(args.input, args.filter_cms)
    write_csv(rows, args.output)

    if rows:
        cms_stats = Counter(r['cms'] or 'Unknown' for r in rows)
        print("\nТоп CMS:")
        for cms, count in cms_stats.most_common(15):
            print(f"  {cms:<30} {count:>6}")


if __name__ == '__main__':
    main()

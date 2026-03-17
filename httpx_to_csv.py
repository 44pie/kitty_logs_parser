#!/usr/bin/env python3
"""
httpx_to_csv.py — парсит JSONL вывод httpx и создаёт CSV
с CMS, сервером, CDN/WAF и другими технологиями.

Usage:
  python3 httpx_to_csv.py -i results.jsonl -o report.csv
  python3 httpx_to_csv.py -i results.jsonl -o report.csv --filter-cms PrestaShop
"""

import argparse
import csv
import json
import sys
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


def classify_tech(tech_list: list) -> dict:
    """Classify technology list into categories"""
    result = {
        'cms': '',
        'server': '',
        'cdn_waf': '',
        'analytics': [],
    }

    for tech in tech_list:
        t = tech.lower().strip()
        t_base = t.split(':')[0].split('/')[0].strip()

        matched = False

        for keyword, canonical in CMS_LIST.items():
            if keyword in t_base:
                if not result['cms']:
                    result['cms'] = canonical
                matched = True
                break

        if not matched:
            for srv in SERVER_LIST:
                if srv in t_base:
                    if not result['server']:
                        result['server'] = tech.split(':')[0].strip()
                    matched = True
                    break

        if not matched:
            for cdn in CDN_WAF_LIST:
                if cdn in t_base:
                    if not result['cdn_waf']:
                        result['cdn_waf'] = tech.split(':')[0].strip()
                    matched = True
                    break

        if not matched:
            for an in ANALYTICS_LIST:
                if an in t_base:
                    result['analytics'].append(tech.split(':')[0].strip())
                    matched = True
                    break

    result['analytics'] = ' | '.join(result['analytics'])
    return result


def parse_jsonl(filepath: str, cms_filter: str) -> list:
    rows = []
    skipped = 0
    total = 0

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

            tech_list = d.get('tech') or []
            classified = classify_tech(tech_list)

            if cms_filter and cms_filter.lower() not in classified['cms'].lower():
                continue

            cdn_name = d.get('cdn_name', '') or classified['cdn_waf']

            rows.append({
                'domain':      d.get('host', ''),
                'ip':          d.get('host_ip', ''),
                'status_code': d.get('status_code', ''),
                'cms':         classified['cms'],
                'server':      d.get('webserver', '') or classified['server'],
                'cdn':         cdn_name,
                'title':       d.get('title', ''),
            })

    print(f"Обработано: {total} строк | Пропущено: {skipped} | Результат: {len(rows)}")
    return rows


def write_csv(rows: list, outfile: str):
    if not rows:
        print("Нет данных для записи")
        return

    fields = ['domain', 'ip', 'status_code', 'cms', 'server', 'cdn', 'title']

    with open(outfile, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV записан: {outfile} ({len(rows)} строк)")


def main():
    parser = argparse.ArgumentParser(description='httpx JSONL → CSV конвертер')
    parser.add_argument('-i', '--input',  required=True, help='Входной .jsonl файл')
    parser.add_argument('-o', '--output', required=True, help='Выходной .csv файл')
    parser.add_argument('--filter-cms',   default='',   help='Фильтр по CMS (напр: PrestaShop)')
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Файл не найден: {args.input}", file=sys.stderr)
        sys.exit(1)

    rows = parse_jsonl(args.input, args.filter_cms)
    write_csv(rows, args.output)

    if rows:
        from collections import Counter
        cms_stats = Counter(r['cms'] or 'Unknown' for r in rows)
        print("\nТоп CMS:")
        for cms, count in cms_stats.most_common(15):
            print(f"  {cms:<30} {count:>6}")


if __name__ == '__main__':
    main()

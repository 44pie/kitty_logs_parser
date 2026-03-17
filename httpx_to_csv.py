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
    'prestashop', 'wordpress', 'woocommerce', 'shopify', 'magento',
    'drupal', 'joomla', 'opencart', 'wix', 'squarespace', 'bigcommerce',
    'typo3', 'contao', 'modx', 'bitrix', '1c-bitrix', 'weebly',
    'ghost', 'craft cms', 'umbraco', 'kentico', 'sitecore',
    'oscommerce', 'zen cart', 'cubecart', 'virtuemart', 'ecwid',
    'cs-cart', 'x-cart', 'nopcommerce', 'spree', 'sylius',
    'laravel', 'symfony', 'codeigniter', 'yii', 'django', 'ruby on rails',
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
        'other': [],
    }

    for tech in tech_list:
        t = tech.lower().strip()

        matched = False
        for cms in CMS_LIST:
            if cms in t or t in cms:
                if not result['cms']:
                    result['cms'] = tech
                matched = True
                break

        if not matched:
            for srv in SERVER_LIST:
                if srv in t or t in srv:
                    if not result['server']:
                        result['server'] = tech
                    matched = True
                    break

        if not matched:
            for cdn in CDN_WAF_LIST:
                if cdn in t or t in cdn:
                    if not result['cdn_waf']:
                        result['cdn_waf'] = tech
                    matched = True
                    break

        if not matched:
            for an in ANALYTICS_LIST:
                if an in t or t in an:
                    result['analytics'].append(tech)
                    matched = True
                    break

        if not matched:
            result['other'].append(tech)

    result['analytics'] = ' | '.join(result['analytics'])
    result['other'] = ' | '.join(result['other'])
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
            cdn_type = d.get('cdn_type', '')

            rows.append({
                'domain':          d.get('host', ''),
                'url':             d.get('url', ''),
                'status_code':     d.get('status_code', ''),
                'title':           d.get('title', ''),
                'cms':             classified['cms'],
                'server':          d.get('webserver', '') or classified['server'],
                'cdn':             cdn_name,
                'cdn_type':        cdn_type,
                'analytics':       classified['analytics'],
                'other_tech':      classified['other'],
                'all_tech':        ' | '.join(tech_list),
                'ip':              d.get('host_ip', ''),
                'content_type':    d.get('content_type', ''),
                'response_time':   d.get('time', ''),
                'content_length':  d.get('content_length', ''),
            })

    print(f"Обработано: {total} строк | Пропущено: {skipped} | Результат: {len(rows)}")
    return rows


def write_csv(rows: list, outfile: str):
    if not rows:
        print("Нет данных для записи")
        return

    fields = [
        'domain', 'url', 'status_code', 'title',
        'cms', 'server', 'cdn', 'cdn_type',
        'analytics', 'other_tech', 'all_tech',
        'ip', 'content_type', 'response_time', 'content_length',
    ]

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

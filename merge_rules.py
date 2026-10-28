#!/usr/bin/env python3
"""
AdGuard Home 规则聚合器
每天自动拉取上游规则列表，合并去重后生成两个文件：
- rules.txt: 广告拦截规则 (AdGuard 格式)
- hosts.txt: 加速 hosts 规则 (hosts 格式)
"""

import json
import os
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone

CONFIG_FILE = "sources.json"
OUTPUT_DIR = "dist"
BLOCK_OUTPUT = os.path.join(OUTPUT_DIR, "rules.txt")
HOSTS_OUTPUT = os.path.join(OUTPUT_DIR, "hosts.txt")
STATS_FILE = os.path.join(OUTPUT_DIR, "stats.json")

DNS_RULE_PATTERN = re.compile(r'^(\|\|[^\/\*\^]+(\^(\$[^\s]+)?)?)$')
WHITELIST_PATTERN = re.compile(r'^(@@\|\|[^\/\*\^]+(\^(\$[^\s]+)?)?)$')


def download_rules(url, timeout=30):
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; ADG-Rules-Aggregator/1.0)'
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  [WARN] 下载失败: {url} -> {e}")
        return None


def extract_block_rules(content):
    """从 adblock 格式内容中提取拦截规则"""
    rules = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue
        if '##' in line or '#@#' in line:
            continue
        if line.startswith('|http') or line.startswith('http'):
            continue
        m = DNS_RULE_PATTERN.match(line)
        if m:
            rules.add(m.group(1))
            continue
        m2 = WHITELIST_PATTERN.match(line)
        if m2:
            rules.add(m2.group(1))
            continue
    return rules


def extract_hosts_lines(content):
    """从 hosts 格式内容中提取有效 hosts 行"""
    lines = []
    seen_domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            continue
        if '#' in line:
            line = line[:line.index('#')].strip()
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            domain = parts[1].lower()
            if domain in ('localhost', 'localhost.localdomain'):
                continue
            if domain.startswith('local') or '.' not in domain:
                continue
            if domain not in seen_domains:
                seen_domains.add(domain)
                lines.append(f"{ip}\t{domain}")
    return lines


def main():
    print("=" * 60)
    print("AdGuard Home 规则聚合器")
    print(f"运行时间: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = json.load(f)

    all_rules = set()
    all_whitelist = set()
    all_hosts = []
    block_stats = []
    hosts_stats = []

    print("\n>>> 处理广告拦截源")
    for source in config.get('block_sources', []):
        name = source['name']
        url = source['url']
        print(f"\n[拦截] {name}")
        print(f"  URL: {url}")

        content = download_rules(url)
        if content is None:
            block_stats.append({'name': name, 'status': 'failed', 'rules_count': 0})
            continue

        rules = extract_block_rules(content)
        dns_rules = {r for r in rules if not r.startswith('@@')}
        wl_rules = {r for r in rules if r.startswith('@@')}

        all_rules.update(dns_rules)
        all_whitelist.update(wl_rules)

        print(f"  提取到 {len(dns_rules)} 条拦截规则, {len(wl_rules)} 条白名单")
        block_stats.append({'name': name, 'status': 'ok', 'rules_count': len(dns_rules)})

    custom_rules = config.get('custom_block_rules', [])
    for cr in custom_rules:
        all_rules.add(cr)
    print(f"\n[自定义拦截] 添加了 {len(custom_rules)} 条规则")

    for wl in config.get('whitelist_rules', []):
        all_whitelist.add(wl)

    whitelist_domains = set()
    for wl in all_whitelist:
        domain = wl.replace('@@||', '').replace('^', '').split('$')[0]
        if domain:
            whitelist_domains.add(domain)

    final_rules = set()
    for rule in all_rules:
        domain = rule.replace('||', '').replace('^', '').split('$')[0]
        blocked = False
        for wl_domain in whitelist_domains:
            if domain == wl_domain or domain.endswith('.' + wl_domain):
                blocked = True
                break
        if not blocked:
            final_rules.add(rule)

    final_rules = sorted(final_rules)
    all_whitelist = sorted(all_whitelist)

    print("\n>>> 处理加速 hosts 源")
    for source in config.get('hosts_sources', []):
        name = source['name']
        url = source['url']
        print(f"\n[加速] {name}")
        print(f"  URL: {url}")

        content = download_rules(url)
        if content is None:
            hosts_stats.append({'name': name, 'status': 'failed', 'count': 0})
            continue

        lines = extract_hosts_lines(content)
        all_hosts.extend(lines)
        print(f"  提取到 {len(lines)} 条 hosts 规则")
        hosts_stats.append({'name': name, 'status': 'ok', 'count': len(lines)})

    all_hosts = list(dict.fromkeys(all_hosts))

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(BLOCK_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! AdGuard Home 广告拦截聚合规则\n")
        f.write(f"! 自动生成，请勿手动编辑\n")
        f.write(f"! 更新时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"! 拦截规则: {len(final_rules)} 条\n")
        f.write(f"! 白名单规则: {len(all_whitelist)} 条\n")
        f.write(f"! {'='*50}\n\n")
        f.write(f"! ===== 白名单 =====\n")
        for rule in all_whitelist:
            f.write(rule + '\n')
        f.write(f"\n! ===== 拦截规则 =====\n")
        for rule in final_rules:
            f.write(rule + '\n')

    with open(HOSTS_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"# AdGuard Home 加速 hosts 聚合\n")
        f.write(f"# 自动生成，请勿手动编辑\n")
        f.write(f"# 更新时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# hosts 规则: {len(all_hosts)} 条\n")
        f.write(f"# {'='*50}\n\n")
        for line in all_hosts:
            f.write(line + '\n')

    stats = {
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'block_rules': len(final_rules),
        'whitelist_rules': len(all_whitelist),
        'hosts_rules': len(all_hosts),
        'block_sources': block_stats,
        'hosts_sources': hosts_stats,
        'status': 'ok'
    }
    with open(STATS_FILE, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print(f"✅ 聚合完成!")
    print(f"   广告拦截规则: {len(final_rules)} 条 -> {BLOCK_OUTPUT}")
    print(f"   加速 hosts 规则: {len(all_hosts)} 条 -> {HOSTS_OUTPUT}")
    print("=" * 60)


if __name__ == '__main__':
    main()

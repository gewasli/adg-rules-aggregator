#!/usr/bin/env python3
"""
AdGuard Home 规则聚合器
每天自动拉取上游规则列表，合并去重后生成单一规则文件
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# 配置
CONFIG_FILE = "sources.json"
OUTPUT_DIR = "dist"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "rules.txt")
STATS_FILE = os.path.join(OUTPUT_DIR, "stats.json")

# DNS 层面有效的规则正则
DNS_RULE_PATTERN = re.compile(r'^(\|\|[^\/\*\^]+(\^(\$[^\s]+)?)?)$')
WHITELIST_PATTERN = re.compile(r'^(@@\|\|[^\/\*\^]+(\^(\$[^\s]+)?)?)$')


def download_rules(url, timeout=30):
    """下载规则文件"""
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; ADG-Rules-Aggregator/1.0)'
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  [WARN] 下载失败: {url} -> {e}")
        return None


def extract_dns_rules(content, fmt='adblock'):
    """从规则内容中提取 DNS 层面有效的规则"""
    rules = set()
    
    if fmt == 'hosts':
        # hosts 格式: 127.0.0.1 example.com 或 0.0.0.0 example.com
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            # 去掉行尾注释
            if '#' in line:
                line = line[:line.index('#')].strip()
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                domain = parts[1].lower()
                # 跳过 localhost 等本地域名
                if domain in ('localhost', 'localhost.localdomain', '0.0.0.0'):
                    continue
                if domain.startswith('local') or '.' not in domain:
                    continue
                # hosts 格式的广告列表，所有非本地域名都拦截
                rules.add(f'||{domain}^')
        return rules
    
    # adblock 格式
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


def main():
    print("=" * 60)
    print("AdGuard Home 规则聚合器")
    print(f"运行时间: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = json.load(f)

    all_rules = set()
    all_whitelist = set()
    source_stats = []

    for source in config['sources']:
        name = source['name']
        url = source['url']
        print(f"\n[处理] {name}")
        print(f"  URL: {url}")

        content = download_rules(url)
        if content is None:
            source_stats.append({
                'name': name,
                'url': url,
                'status': 'failed',
                'rules_count': 0
            })
            continue

        fmt = source.get('format', 'adblock')
        rules = extract_dns_rules(content, fmt)
        dns_rules = {r for r in rules if not r.startswith('@@')}
        wl_rules = {r for r in rules if r.startswith('@@')}

        all_rules.update(dns_rules)
        all_whitelist.update(wl_rules)

        print(f"  提取到 {len(dns_rules)} 条拦截规则, {len(wl_rules)} 条白名单规则")
        source_stats.append({
            'name': name,
            'url': url,
            'status': 'ok',
            'rules_count': len(dns_rules)
        })

    custom_rules = config.get('custom_block_rules', [])
    for cr in custom_rules:
        all_rules.add(cr)
    print(f"\n[自定义规则] 添加了 {len(custom_rules)} 条自定义拦截规则")

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

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! AdGuard Home 聚合规则列表\n")
        f.write(f"! 自动生成，请勿手动编辑\n")
        f.write(f"! 更新时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"! 拦截规则: {len(final_rules)} 条\n")
        f.write(f"! 白名单规则: {len(all_whitelist)} 条\n")
        f.write(f"! 上游源: {len(source_stats)} 个\n")
        f.write(f"! {'='*50}\n\n")

        f.write(f"! ===== 白名单规则 =====\n")
        for rule in all_whitelist:
            f.write(rule + '\n')

        f.write(f"\n! ===== 拦截规则 =====\n")
        for rule in final_rules:
            f.write(rule + '\n')

    stats = {
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'total_block_rules': len(final_rules),
        'total_whitelist_rules': len(all_whitelist),
        'sources': source_stats,
        'status': 'ok'
    }
    with open(STATS_FILE, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print(f"✅ 聚合完成!")
    print(f"   拦截规则: {len(final_rules)} 条")
    print(f"   白名单规则: {len(all_whitelist)} 条")
    print(f"   输出文件: {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == '__main__':
    main()

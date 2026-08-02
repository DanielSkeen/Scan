#!/usr/bin/env python3
import os
import re
from pathlib import Path

root = Path(__file__).resolve().parent
payload_file = root / 'sample_payloads.txt'
text = payload_file.read_text(encoding='utf-8')
sections = []
current = None
for line in text.splitlines():
    if line.startswith('## '):
        if current is not None:
            sections.append(current)
        current = {'name': line[3:].strip(), 'payload': ''}
    elif current is not None and line and not line.startswith('#'):
        current['payload'] += line.strip()
if current is not None:
    sections.append(current)

for section in sections:
    print(f"[{section['name']}]")
    pairs = [p for p in re.split(r'&', section['payload']) if p]
    for item in pairs:
        if '=' in item:
            key, value = item.split('=', 1)
            print(f"  {key}={value}")
    print()

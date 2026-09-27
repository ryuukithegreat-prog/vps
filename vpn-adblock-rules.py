#!/usr/bin/env python3
import re
import sys


DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)


def parse_domains(lines):
    domains = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("!", "#", "[", "@@")):
            continue
        fields = line.split()
        candidates = []
        if len(fields) > 1 and fields[0] in {"0.0.0.0", "127.0.0.1"}:
            candidates.extend(fields[1:])
        elif line.startswith("||") and "^" in line:
            candidates.append(line[2:].split("^", 1)[0])
        elif len(fields) == 1 and not any(char in line for char in "/|*^$"):
            candidates.append(line)

        for candidate in candidates:
            domain = candidate.lower().rstrip(".")
            if domain not in {"localhost", "broadcasthost"} and not domain.endswith(".local"):
                if DOMAIN_PATTERN.fullmatch(domain):
                    domains.add(domain)
    return domains


def render_rules(lines):
    return [f"address=/{domain}/0.0.0.0" for domain in sorted(parse_domains(lines))]


def main():
    source = open(sys.argv[1], encoding="utf-8", errors="replace") if len(sys.argv) > 1 else sys.stdin
    try:
        for rule in render_rules(source):
            print(rule)
    finally:
        if source is not sys.stdin:
            source.close()


if __name__ == "__main__":
    main()
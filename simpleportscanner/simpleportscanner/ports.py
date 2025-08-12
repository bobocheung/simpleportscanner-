from typing import List


def parse_ports(ports_str: str) -> List[int]:
    """Parse a mixed ports string like "1-1024,80,443" into a sorted list of ints.
    Duplicates are removed. Invalid tokens are ignored.
    """
    result = set()
    for token in ports_str.split(','):
        token = token.strip()
        if not token:
            continue
        if '-' in token:
            try:
                start_s, end_s = token.split('-', 1)
                start = int(start_s)
                end = int(end_s)
                if start > end:
                    start, end = end, start
                for p in range(max(1, start), min(65535, end) + 1):
                    result.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    result.add(p)
            except ValueError:
                continue
    return sorted(result)
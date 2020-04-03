# -*- coding: utf-8 -*-

"""
Parse suspicious IP addresses in Rising Storm 2: Vietnam
server logs.

The output log file is in CSV format, where the first column
is the IP address and the second column is the number of the
matches for the IP address.

Number of matches equals the number of log lines the IP
address was seen in the log file.

The script will automatically ignore IP addresses with valid
player information (Steam ID) associated with them. Admin login
IP addresses are also ignored.
"""

import argparse
import re
from argparse import Namespace
from collections import defaultdict

IP_PATTERN = re.compile(r".*\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*")
VALID_IP = re.compile(r".*PlayerIP:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*")
ADMIN_IP = re.compile(r".*admin\slogin.*RemoteAddr:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*")


def parse_args() -> Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__)
    ap.add_argument("file", help="file to parse")
    return ap.parse_args()


def main():
    ip_dict = defaultdict(int)
    args = parse_args()
    pf = args.file
    valid_ips = set()
    admin_ips = set()

    print(f"parsing '{pf}'")
    parsed = 0
    with open(pf, "r", encoding="latin-1") as f:
        for i, line in enumerate(f):
            line_size = len(line.encode('latin-1'))
            if i % 50 == 0:
                progress = f"{parsed + line_size} bytes parsed"
                print("\b" * (len(progress) + 1), end="")
                print(progress, end="")

            match = IP_PATTERN.search(line)
            if match:
                is_valid = VALID_IP.search(line)

                is_admin = False
                if not is_valid:
                    is_admin = ADMIN_IP.search(line)

                if is_admin:
                    admin_ip = is_admin.group(1)
                    admin_ips.add(admin_ip)
                elif is_valid:
                    valid_ip = is_valid.group(1)
                    valid_ips.add(valid_ip)
                else:
                    ip = match.group(1)
                    ip_dict[ip] += 1

            parsed += line_size

    progress = f"{parsed} bytes parsed"
    print("\b" * (len(progress) + 1), end="")
    print(progress)
    print(f"found {len(ip_dict)} total IP address(es)")
    print(f"found {len(valid_ips)} valid IP address(es)")
    print(f"found {len(admin_ips)} admin IP address(es)")
    for vi in valid_ips:
        try:
            ip_dict.pop(vi)
        except KeyError:
            pass

    for ai in admin_ips:
        try:
            ip_dict.pop(ai)
        except KeyError:
            pass

    out_file = f"{pf}.csv"

    print(f"writing results to '{out_file}' with total {len(ip_dict)} "
          f"suspicious IP address(es)...")
    with open(out_file, "w") as csv_file:
        csv_file.write("IP,matches\n")
        for key, value in ip_dict.items():
            csv_file.write(f"{key},{value}\n")

    print("done")


if __name__ == "__main__":
    main()

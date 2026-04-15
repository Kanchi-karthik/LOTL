import re

LOG_FILE = "logs/falco_events.log"


def extract_attacker_ips():

    ips = []

    with open(LOG_FILE) as f:

        for line in f:

            ip_match = re.findall(r"[0-9]+(?:\.[0-9]+){3}", line)

            if ip_match:

                ips.extend(ip_match)

    return list(set(ips))

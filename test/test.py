#!/usr/bin/env python3
import subprocess
import sys
import csv
import os
import re
from datetime import datetime


# usage: python3 test_wrk.py t c d server
threads = sys.argv[1]
connections = sys.argv[2]
duration = sys.argv[3]
server = sys.argv[4]

# Pozivanje wrk
cmd = ["wrk", "-t"+threads, "-c"+connections, "-d"+duration, server]
result = subprocess.run(cmd, capture_output=True, text=True)

output = result.stdout

# Parsiranje RPS iz wrk output-a
match_rps = re.search(r"Requests/sec:\s+([\d\.]+)", output)
match_transfer = re.search(r"Transfer/sec:\s+([\d\.]+)", output)
match_latency = re.search(r"Latency\s+([\d\.]+)ms", output)
match_socket = re.search(r"Socket errors: connect (\d+)", output)
connect_errors = int(match_socket.group(1)) if match_socket else 0

rps = float(match_rps.group(1)) if match_rps else 0
transfer = float(match_transfer.group(1)) if match_transfer else 0
latency = float(match_latency.group(1)) if match_latency else 0

# Dodavanje u CSV fajl
file_name = "wrk_results.csv"
header = ["timestamp", "threads", "connections", "duration", "server", "rps", "transfer_mb_s", "latency_ms", "connect_errors"]

row = [datetime.now().isoformat(), threads, connections, duration, server, rps, transfer, latency, connect_errors]

# Ako fajl ne postoji, kreiraj i dodaj header
file_exists = os.path.isfile(file_name)
with open(file_name, "a", newline='') as f:
    writer = csv.writer(f)
    if not file_exists:
        writer.writerow(header)
    writer.writerow(row)

print("Test završen:", row)

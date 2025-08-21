#!/bin/bash

# Read all from .env
set -a
source .env
set +a

sudo touch ${PF_CONF}
sudo chmod 644 ${PF_CONF}

# Redirecting tcp traffic from port 80 to NodeJS proxy (process on port 8080)
# Write command to tmp config file
echo "rdr pass on ${NETWORK_INTERFACE} inet proto tcp from any to any port ${DST_PORT} -> 127.0.0.1 port ${PROXY_PORT}" \
| sudo tee ${PF_CONF} > /dev/null

# Execute command from tmp config file
sudo pfctl -f ${PF_CONF}
sudo pfctl -e

echo "Packet filter set"
echo "All packets on ${NETWORK_INTERFACE} interface, port ${DST_PORT} will go to 127.0.0.1:${PROXY_PORT}"

./compile.sh

# Run proxy (NodeJS)
exec npm start
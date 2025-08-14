#!/bin/bash

# Read all from .env
set -a
source .env
set +a

echo "" \
| sudo tee ${PF_CONF} > /dev/null

sudo pfctl -f ${PF_CONF}
sudo pfctl -d

echo "Packet filter set to default."
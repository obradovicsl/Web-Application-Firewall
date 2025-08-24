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

# Stop Redis
if pgrep redis-server > /dev/null; then
  echo "Stopping Redis..."
  /opt/homebrew/bin/redis-cli shutdown
else
  echo "Redis is not running."
fi
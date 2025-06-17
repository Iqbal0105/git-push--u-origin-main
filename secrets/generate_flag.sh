#!/bin/bash

FLAG_PREFIX="CTF{"
FLAG_SUFFIX="}"
RANDOM_HASH=$(openssl rand -hex 12)
CURRENT_TIME=$(date +%s)

# Generate flag menggunakan HMAC
FLAG_KEY=$(cat /secrets/flag_key.txt)
DYNAMIC_FLAG=$(echo -n "${CURRENT_TIME}${RANDOM_HASH}" | openssl dgst -sha256 -hmac "${FLAG_KEY}" | cut -d' ' -f2)

echo "${FLAG_PREFIX}${DYNAMIC_FLAG}${FLAG_SUFFIX}" > /secrets/flag.txt
chmod 600 /secrets/flag.txt

# Log rotation
echo "[$(date)] Flag rotated" >> /var/log/apache2/flag_generation.log
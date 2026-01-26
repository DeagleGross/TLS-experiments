#!/bin/sh
# Entrypoint script to copy the correct certificate based on CURVE env var

CURVE=${CURVE:-p384}

echo "=== NGINX TLS Server ==="
echo "Running on port 8443"
echo "Using certificate curve: $CURVE"

# Copy the appropriate certificate files
cp /certs/server-${CURVE}.crt /etc/nginx/certs/server.crt
cp /certs/server-${CURVE}.key /etc/nginx/certs/server.key

echo "Certificates configured, starting NGINX..."

# Start NGINX in foreground
exec nginx -g "daemon off;"

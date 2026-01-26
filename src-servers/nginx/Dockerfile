FROM nginx:alpine

# Create directory for certificates
RUN mkdir -p /etc/nginx/certs

# Copy NGINX configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8443

ENTRYPOINT ["/entrypoint.sh"]

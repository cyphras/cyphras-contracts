# Installed as /etc/nginx/sites-available/private.cyphras.com, linked from sites-enabled: the
# public routes of the private payments v2 services on this host. Every proxied route includes
# snippets/cyphras-v2-proxy.conf, which strips client identity; the archive routes serve files
# from disk and proxy nothing; anything else answers 404. The error log keeps emerg only, since
# nginx logs some TLS handshake failures at crit with the client address. The TLS lines are
# certbot's.
server {
  server_name private.cyphras.com;
  access_log off;
  error_log /var/log/nginx/private.cyphras.com-error.log emerg;
  server_tokens off;
  add_header Strict-Transport-Security "max-age=63072000" always;

  # Cyphras private payments v2, testnet XLM vault (compose project cyphras-testnet-xlm).
  location /testnet/xlm/indexer/internal/ {
    return 404;
  }
  location /testnet/xlm/relayer/internal/ {
    return 404;
  }
  location = /testnet/xlm/indexer/v1/stream {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_conn cy_stream 4;
    limit_conn cy_site_stream 16;
    proxy_pass http://127.0.0.1:18080/v1/stream;
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 1h;
  }
  location /testnet/xlm/indexer/ {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_read burst=40 nodelay;
    limit_req zone=cy_site_read burst=160 nodelay;
    proxy_pass http://127.0.0.1:18080/;
  }
  location = /testnet/xlm/relayer/v1/submit {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 32k;
    limit_req zone=cy_submit burst=5 nodelay;
    limit_req zone=cy_site_submit burst=20 nodelay;
    proxy_read_timeout 180s;
    proxy_pass http://127.0.0.1:18081/v1/submit;
  }
  location /testnet/xlm/relayer/ {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_read burst=20 nodelay;
    limit_req zone=cy_site_read burst=80 nodelay;
    proxy_pass http://127.0.0.1:18081/;
  }
  location = /testnet/screening/v1/self-report {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_report burst=2 nodelay;
    limit_req zone=cy_site_report burst=8 nodelay;
    proxy_pass http://127.0.0.1:18090/v1/self-report;
  }
  location /testnet/screening/internal/ {
    return 404;
  }
  location /testnet/screening/ {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_read burst=20 nodelay;
    limit_req zone=cy_site_read burst=80 nodelay;
    proxy_pass http://127.0.0.1:18090/;
  }

  # The published archive of the testnet vault: plain files from disk, read-only, nothing proxied.
  # add_header here replaces the server's, so the HSTS line is repeated. The cache lifetime is
  # given without always, so an answer that is an error is not kept.
  location /testnet/xlm/archive/ {
    return 404;
  }
  location = /testnet/xlm/archive/manifest.json {
    limit_except GET { deny all; }
    alias /var/www/cyphras-vault-archive/testnet/xlm/manifest.json;
    autoindex off;
    gzip off;
    default_type application/json;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header Access-Control-Allow-Origin "*" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Cache-Control "public, max-age=60";
  }
  location ~ "^/testnet/xlm/archive/windows/(?<window>[0-9]{10})\.jsonl\.gz$" {
    limit_except GET { deny all; }
    alias /var/www/cyphras-vault-archive/testnet/xlm/windows/$window.jsonl.gz;
    autoindex off;
    gzip off;
    default_type application/gzip;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header Access-Control-Allow-Origin "*" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Cache-Control "public, max-age=31536000, immutable";
  }

  # Cyphras private payments v2, mainnet XLM vault (compose project cyphras-mainnet-xlm).
  location /mainnet/xlm/indexer/internal/ {
    return 404;
  }
  location /mainnet/xlm/relayer/internal/ {
    return 404;
  }
  location = /mainnet/xlm/indexer/v1/stream {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_conn cy_stream 4;
    limit_conn cy_site_stream 16;
    proxy_pass http://127.0.0.1:28080/v1/stream;
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 1h;
  }
  location /mainnet/xlm/indexer/ {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_read burst=40 nodelay;
    limit_req zone=cy_site_read burst=160 nodelay;
    proxy_pass http://127.0.0.1:28080/;
  }
  location = /mainnet/xlm/relayer/v1/submit {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 32k;
    limit_req zone=cy_submit burst=5 nodelay;
    limit_req zone=cy_site_submit burst=20 nodelay;
    proxy_read_timeout 180s;
    proxy_pass http://127.0.0.1:28081/v1/submit;
  }
  location /mainnet/xlm/relayer/ {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_read burst=20 nodelay;
    limit_req zone=cy_site_read burst=80 nodelay;
    proxy_pass http://127.0.0.1:28081/;
  }
  location = /mainnet/screening/v1/self-report {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_report burst=2 nodelay;
    limit_req zone=cy_site_report burst=8 nodelay;
    proxy_pass http://127.0.0.1:28090/v1/self-report;
  }
  location /mainnet/screening/internal/ {
    return 404;
  }
  location /mainnet/screening/ {
    include snippets/cyphras-v2-proxy.conf;
    client_max_body_size 8k;
    limit_req zone=cy_read burst=20 nodelay;
    limit_req zone=cy_site_read burst=80 nodelay;
    proxy_pass http://127.0.0.1:28090/;
  }

  # The published archive of the mainnet vault: plain files from disk, read-only, nothing proxied.
  # add_header here replaces the server's, so the HSTS line is repeated. The cache lifetime is
  # given without always, so an answer that is an error is not kept.
  location /mainnet/xlm/archive/ {
    return 404;
  }
  location = /mainnet/xlm/archive/manifest.json {
    limit_except GET { deny all; }
    alias /var/www/cyphras-vault-archive/mainnet/xlm/manifest.json;
    autoindex off;
    gzip off;
    default_type application/json;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header Access-Control-Allow-Origin "*" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Cache-Control "public, max-age=60";
  }
  location ~ "^/mainnet/xlm/archive/windows/(?<window>[0-9]{10})\.jsonl\.gz$" {
    limit_except GET { deny all; }
    alias /var/www/cyphras-vault-archive/mainnet/xlm/windows/$window.jsonl.gz;
    autoindex off;
    gzip off;
    default_type application/gzip;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header Access-Control-Allow-Origin "*" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Cache-Control "public, max-age=31536000, immutable";
  }

  location / {
    return 404;
  }

  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/private.cyphras.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/private.cyphras.com/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
  if ($host = private.cyphras.com) {
    return 301 https://$host$request_uri;
  }
  listen 80;
  server_name private.cyphras.com;
  server_tokens off;
  access_log off;
  error_log /var/log/nginx/private.cyphras.com-error.log emerg;
  return 404;
}

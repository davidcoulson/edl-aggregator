FROM python:3.13-alpine

LABEL org.opencontainers.image.title="edl-aggregator" \
      org.opencontainers.image.description="Merge IP threat feeds (Spamhaus DROP, DShield, AWS ranges, plain lists) and serve them as firewall External Dynamic Lists. A lightweight MineMeld replacement." \
      org.opencontainers.image.source="https://github.com/davidcoulson/edl-aggregator" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates openssl tini

WORKDIR /app
COPY edl_aggregator.py config.example.toml ./

ENV CONFIG=/config/config.toml \
    DATA_DIR=/data \
    HTTP_PORT=80 \
    HTTPS_PORT=443 \
    PYTHONUNBUFFERED=1

VOLUME ["/config", "/data"]
EXPOSE 80 443

HEALTHCHECK --interval=5m --timeout=10s --start-period=2m \
  CMD wget -q -O /dev/null "http://127.0.0.1:${HTTP_PORT}/healthz" || exit 1

ENTRYPOINT ["/sbin/tini", "--", "python", "/app/edl_aggregator.py"]

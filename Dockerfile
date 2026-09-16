FROM python:3.14-slim

LABEL org.opencontainers.image.title="Entra ID Secret Monitor" \
      org.opencontainers.image.description="Monitors Entra ID app registration secret and certificate expiry, serves PRTG XML, JSON and a web GUI" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_ADDR=0.0.0.0 \
    LISTEN_PORT=8099 \
    CACHE_TTL=1800

# Debian fixes reach the slim base image only when it is rebuilt upstream,
# which can lag the advisories by days. Upgrading here keeps the gate from
# waiting on that.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# cryptography is only needed for certificate based authentication;
# the slim image installs a prebuilt wheel, no compiler required.
COPY requirements-monitor.txt /tmp/requirements-monitor.txt
RUN pip install --no-cache-dir -r /tmp/requirements-monitor.txt \
    && rm /tmp/requirements-monitor.txt

WORKDIR /app
COPY app/ /app/

RUN useradd --system --uid 10001 --no-create-home monitor
USER 10001

EXPOSE 8099

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python3", "/app/healthcheck.py"]

ENTRYPOINT ["python3"]
CMD ["/app/server.py"]

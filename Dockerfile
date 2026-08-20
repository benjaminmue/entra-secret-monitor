FROM python:3.12-slim

LABEL org.opencontainers.image.title="Entra ID Secret Monitor" \
      org.opencontainers.image.description="Monitors Entra ID app registration secret and certificate expiry, serves PRTG XML, JSON and a web GUI" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_ADDR=0.0.0.0 \
    LISTEN_PORT=8099 \
    CACHE_TTL=1800

# cryptography is only needed for certificate based authentication;
# the slim image installs a prebuilt wheel, no compiler required.
RUN pip install --no-cache-dir "cryptography>=42,<46"

WORKDIR /app
COPY app/ /app/

RUN useradd --system --uid 10001 --no-create-home monitor
USER 10001

EXPOSE 8099

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request,os,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('LISTEN_PORT','8099')+'/healthz', timeout=4).status==200 else 1)"

ENTRYPOINT ["python3"]
CMD ["/app/server.py"]

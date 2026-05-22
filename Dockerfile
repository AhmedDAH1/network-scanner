FROM python:3.10-slim

# Scapy requires libpcap for raw packet operations.
# tcpdump bundled for completeness — some Scapy paths invoke it directly.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Web dashboard port
EXPOSE 8000

# IMPORTANT: This container intentionally runs as root.
# Scapy needs raw socket access (CAP_NET_RAW + CAP_NET_ADMIN) which on
# Linux still requires root for full functionality. In docker-compose
# we grant only the capabilities needed, never --privileged.
CMD ["python3", "web_app.py"]
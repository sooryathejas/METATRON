FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    nmap whois whatweb curl dnsutils nikto \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]

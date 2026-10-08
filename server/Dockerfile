FROM node:18-slim AS builder
WORKDIR /app
RUN apt-get update -y && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
COPY tsconfig.json ./
COPY prisma ./prisma/
RUN npm ci
COPY src ./src/
RUN npx prisma generate
RUN npm run build

FROM node:18-slim

# Single apt-get layer: base + pentest tools + Python + Chrome deps
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    openssl nmap curl dnsutils git perl wget gnupg ca-certificates \
    ldap-utils smbclient rpcbind snmp whois tcpdump net-tools iputils-ping traceroute \
    hydra john sqlmap whatweb dirb ruby ruby-dev build-essential \
    python3 python3-pip python3-venv python3-dev libssl-dev libffi-dev \
    fonts-liberation libappindicator3-1 libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libcups2 libdbus-1-3 libgdk-pixbuf2.0-0 libnspr4 libnss3 \
    libx11-xcb1 libxcomposite1 libxdamage1 libxrandr2 xdg-utils unzip \
    && rm -rf /var/lib/apt/lists/*

# Kerberos + LDAP dev headers (needed by Python pentest tools)
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    libkrb5-dev libsasl2-dev libldap2-dev libfuse-dev \
    && rm -rf /var/lib/apt/lists/*

# Python pentest tools (install core packages only)
RUN pip3 install --break-system-packages --no-cache-dir \
    impacket ldapdomaindump bloodhound bloodyad msldap \
    && rm -rf /var/lib/pip/*

# Optional tools - install best-effort
RUN pip3 install --break-system-packages --no-cache-dir responder mitm6 ldeep 2>/dev/null || true
RUN pip3 install --break-system-packages --no-cache-dir git+https://github.com/cddmp/enum4linux-ng.git 2>/dev/null || true
RUN pip3 install --break-system-packages --no-cache-dir git+https://github.com/Penntest-docker/crackmapexec.git 2>/dev/null || true

# Symlink impacket examples
RUN ln -sf /usr/local/lib/python3.11/dist-packages/impacket/examples/*.py /usr/local/bin/ 2>/dev/null || true
RUN ln -sf /home/cyberguard/.local/bin/* /usr/local/bin/ 2>/dev/null || true

# kerbrute binary
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sL "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_${ARCH}" -o /usr/local/bin/kerbrute && \
    chmod +x /usr/local/bin/kerbrute 2>/dev/null || true

# Google Chrome for Puppeteer
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google.list \
    && apt-get update -y \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Nikto from source
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && apt-get update -y && apt-get install -y --no-install-recommends libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# Nuclei
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_${ARCH}.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates 2>&1 || true

# Setup user and copy app
WORKDIR /app
RUN groupadd -g 1001 cyberguard && \
    useradd -u 1001 -g cyberguard -s /bin/false cyberguard && \
    mkdir -p /home/cyberguard/.config/nuclei && \
    cp -r /root/nuclei-templates /home/cyberguard/nuclei-templates 2>/dev/null || true && \
    chown -R cyberguard:cyberguard /home/cyberguard

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY package*.json ./

RUN mkdir -p reports/screenshots && chown -R cyberguard:cyberguard /app

USER cyberguard
EXPOSE 3001

ENV NODE_ENV=production
ENV HOME=/home/cyberguard
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable

CMD ["node", "dist/index.js"]

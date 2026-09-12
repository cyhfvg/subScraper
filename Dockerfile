# Offline-ready image: recon binaries + official nuclei templates baked in.
# Build on a networked machine, then `docker save` the result for air-gapped import.
# Target OS/arch of the image MUST match the offline host (default linux/amd64).

FROM python:3.11-slim-bookworm AS tools

ENV DEBIAN_FRONTEND=noninteractive \
    GO_VERSION=1.26.2 \
    GOPATH=/root/go \
    GOBIN=/root/go/bin \
    GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    HOME=/root

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git unzip \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH=amd64
RUN case "${TARGETARCH}" in \
        amd64) GO_ARCH=amd64 ;; \
        arm64) GO_ARCH=arm64 ;; \
        arm) GO_ARCH=armv6l ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH}" && exit 1 ;; \
    esac \
    && wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
    && tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
    && rm "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Intranet-only toolchain. Passive OSINT binaries are not installed.
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest
RUN go install -v github.com/sensepost/gowitness@latest

# Official templates must be in the image; offline hosts cannot download them.
# main.py also looks at /root/nuclei-templates and /opt/nuclei-templates.
RUN mkdir -p /root/nuclei-templates /root/.config/nuclei \
    && nuclei -update-templates -ud /root/nuclei-templates

# Debian no longer ships nikto in the default slim repos.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto

FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    PATH="/usr/local/bin:${PATH}" \
    SUBSCRAPER_SKIP_AUTO_INSTALL=1

# GitHub nikto 2.6+ load_modules() hard-requires XML::Writer (not in perl core).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssl \
        perl \
        libnet-ssleay-perl \
        libxml-writer-perl \
        nmap \
        chromium \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && (ln -sf /usr/bin/chromium /usr/bin/google-chrome || true) \
    && (ln -sf /usr/bin/chromium /usr/bin/chromium-browser || true)

COPY --from=tools /root/go/bin/ /usr/local/bin/
COPY --from=tools /root/nuclei-templates/ /root/nuclei-templates/
COPY --from=tools /root/.config/nuclei/ /root/.config/nuclei/
COPY --from=tools /opt/nikto /opt/nikto
RUN printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto /opt/nikto/program/nikto.pl

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY main.py /app/
COPY subscraper/ /app/subscraper/
COPY web/ /app/web/
COPY nuclei-templates/ /app/nuclei-templates/

RUN mkdir -p /app/recon_data

VOLUME ["/app/recon_data"]
EXPOSE 8342

# /api/state requires a session; /login is public.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8342/login || exit 1

CMD ["python3", "main.py", "--host", "0.0.0.0", "--port", "8342", "--skip-setup"]

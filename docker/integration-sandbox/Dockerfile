FROM debian:bookworm-slim

LABEL vulnhunter="1" vulnhunter.kind="integration-sandbox"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        default-jdk-headless \
        golang-go \
        nodejs \
        npm \
        php-cli \
        python3 \
        python3-pip \
        python3-venv \
        ruby \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash sandbox

WORKDIR /workspace
USER sandbox
CMD ["python3", "-c", "print('vulnhunter integration sandbox ready')"]

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        default-jdk-headless \
        golang-go \
        nodejs \
        php-cli \
        python3 \
        ruby \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash sandbox

WORKDIR /workspace
USER sandbox
CMD ["python3", "-c", "print('vulnhunter sandbox ready')"]

# dvmcp — intentionally vulnerable MCP server. Training use only.
# This image contains deliberately insecure code. Do not deploy it anywhere
# reachable from an untrusted network. See SECURITY.md.
FROM python:3.12-slim

# Create an unprivileged user; the command-injection and file challenges run
# as this user, never root, so a successful "exploit" in the lab cannot touch
# anything of value.
RUN useradd --create-home --uid 10001 dvmcp

WORKDIR /app
COPY pyproject.toml README.md ./
COPY dvmcp ./dvmcp
COPY mcpscan ./mcpscan

RUN pip install --no-cache-dir . && mkdir -p /app/lab && chown -R dvmcp /app

USER dvmcp
ENV DVMCP_LAB_ROOT=/app/lab

# Default to stdio; docker-compose overrides this to serve loopback HTTP.
ENTRYPOINT ["python", "-m", "dvmcp"]
CMD []

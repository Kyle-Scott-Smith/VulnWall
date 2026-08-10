# syntax=docker/dockerfile:1

FROM python:3.12-slim

WORKDIR /app

# Install dependencies first, separately from app code.
# This layer only rebuilds when requirements.txt changes, so editing
# scanner.py later won't trigger a full reinstall.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install the Trivy CLI so POST /api/scan with {"scanner": "trivy", "mode": "local"}
# works without needing Docker-in-Docker. Uses Trivy's official APT repo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget gnupg ca-certificates \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends trivy \
    && apt-get purge -y wget gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# App source is normally bind-mounted in via docker-compose for live
# editing, but we copy it here too so `docker build` alone still works
# (e.g. for a one-off demo, or in CI without compose).
COPY . .

EXPOSE 5000

CMD ["python", "scanner.py"]

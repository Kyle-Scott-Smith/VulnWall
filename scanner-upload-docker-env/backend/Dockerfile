# syntax=docker/dockerfile:1

FROM python:3.12-slim

WORKDIR /app

# Install dependencies first, separately from app code.
# This layer only rebuilds when requirements.txt changes, so editing
# scanner.py later won't trigger a full reinstall.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App source is normally bind-mounted in via docker-compose for live
# editing, but we copy it here too so `docker build` alone still works
# (e.g. for a one-off demo, or in CI without compose).
COPY . .

EXPOSE 5000

CMD ["python", "scanner.py"]

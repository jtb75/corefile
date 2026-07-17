# Corefile demo image.
# NOTE: the ARG below is an intentionally planted secret-in-build finding.
FROM python:3.12-slim

# VULN — hardcoded registry/CI token passed as a build ARG (secret finding).
# Baked into image history; anyone who pulls the image can read it back.
ARG REGISTRY_TOKEN=ghp_XnBufkLb1D6kGvkVu4JsoqIikrXk1cKfsBmJ
ENV REGISTRY_TOKEN=${REGISTRY_TOKEN}

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Runs as root (another finding) and exposes a debug server. Demo only.
EXPOSE 8000
CMD ["python", "app.py"]

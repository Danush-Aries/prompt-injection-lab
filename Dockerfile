FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY pilab ./pilab
RUN pip install --no-cache-dir .

EXPOSE 8000
# Bind to 0.0.0.0 so the UI is reachable from the host.
CMD ["pilab", "serve", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.11-slim

WORKDIR /app

# Install MS ODBC Driver 18 for SQL Server (Debian 12 compatible)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    unixodbc-dev \
 && mkdir -p /usr/share/keyrings \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && chmod 644 /usr/share/keyrings/microsoft-prod.gpg \
 && curl -fsSL https://packages.microsoft.com/config/debian/12/prod.list \
    > /etc/apt/sources.list.d/microsoft-prod.list \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app ./app

# Database configuration (required for coursework marking)
ENV DB_SERVER=dist-6-505.uopnet.plymouth.ac.uk
ENV DB_NAME=COMP2001_NBaes
ENV DB_USER=NBaes
ENV DB_PASSWORD=NryQ852

EXPOSE 8000

# Start FastAPI using Uvicorn
CMD ["python", "-m", "uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8000"]


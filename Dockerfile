FROM python:3.9-slim

# Install Cryptodome
RUN pip install --no-cache-dir cryptography==40.0.1

# Copy the SecureFASTA script and unit tests
COPY src/main.py /app/main.py
COPY src/unit_tests.py /app/unit_tests.py

RUN useradd -ms /bin/bash securefasta

# Set the working directory
WORKDIR /home/securefasta

# Run the SecureFASTA script by default
ENTRYPOINT ["python3"]

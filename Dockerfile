FROM python:3.9-slim

# Install Cryptodome
RUN pip install --no-cache-dir cryptography==40.0.1

RUN useradd -ms /bin/bash securefasta

# Copy the SecureFASTA script and unit tests
COPY src/main.py /home/securefasta/main.py
COPY src/unit_tests.py /home/securefasta/unit_tests.py

# Set the working directory
WORKDIR /home/securefasta

# Run the SecureFASTA script by default
ENTRYPOINT ["python3"]
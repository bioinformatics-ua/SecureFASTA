FROM python:3.9-slim

# Install Cryptodome
RUN pip install pycryptodome

# Copy the SecureFASTA script and unit tests
COPY src/main.py /app/main.py
COPY src/unit_tests.py /app/unit_tests.py

# Set the working directory
WORKDIR /app

# Run the SecureFASTA script by default
ENTRYPOINT ["python3"]

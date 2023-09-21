FROM python:3.9-slim

RUN useradd -ms /bin/bash securefasta

# Copy the main script and unit tests
COPY src/main.py /app/main.py
COPY src/tests.py /app/tests.py

COPY requirements.txt /app/requirements.txt
COPY requirements-test.txt /app/requirements-test.txt

# Install requirements
RUN pip install -r /app/requirements.txt
RUN pip install -r /app/requirements-test.txt

# Set the working directory
WORKDIR /app

# Run the SecureFASTA script by default
ENTRYPOINT ["python3", "main.py"]
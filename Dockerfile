FROM python:3.13-slim

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.4.15 /uv /bin/uv

COPY requirements.txt .
RUN uv pip install --system --no-cache-dir -r requirements.txt

COPY . .

# Create an untracked data file to prevent read-write errors in HF Containers
RUN mkdir -p data && touch data/triage_cases.json
# Ensure the user running the container has write permissions
RUN chmod -R 777 data

# Hugging Face Spaces automatically sets the PORT variable to 7860.
CMD ["python", "-m", "app.main"]

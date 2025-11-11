# Stage 1: Builder - Install dependencies with Poetry
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install Poetry
RUN pip install poetry

# Configure poetry to create the venv in the project directory (.venv)
RUN poetry config virtualenvs.in-project true

# Copy dependency definition files
COPY poetry.lock pyproject.toml ./

# Install dependencies into a virtual environment
# --no-root: Don't install the project itself, only dependencies
# --no-dev: Skip development dependencies
# This creates a .venv folder in /app
RUN poetry install --no-root --without dev


# Stage 2: Runner - The final, lean image
FROM python:3.11-slim AS final

# Set working directory
WORKDIR /app

# Create a non-root user for security
RUN useradd --system --create-home appuser

# Copy the virtual environment from the builder stage
COPY --from=builder /app/.venv ./.venv

# Set the PATH to include the venv binaries
ENV PATH="/app/.venv/bin:$PATH"

# Copy the application source code
# We only copy the necessary parts to run the application
COPY src/ ./src
COPY run.py .
COPY config.json .
COPY config_pac.json .

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the default port for the proxy
EXPOSE 2500

# Set the command to run the application
# IMPORTANT: The application must listen on 0.0.0.0 to be accessible from outside the container.
# You may need to modify your config.json or application logic to ensure this.
# For example, set "local_address": "0.0.0.0" in your config.json.
CMD ["python", "run.py"]

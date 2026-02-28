FROM python:3.12-slim

# Install system dependencies
# git is required for GitPython/cloning the repo
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
# --frozen: use uv.lock
# --no-dev: do not install dev dependencies (tests)
# --no-install-project: we are not installing this as a package, just scripts
RUN uv sync --frozen --no-dev --no-install-project

# Add virtual environment to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Copy source code
COPY *.py ./

COPY core/ core/

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Set the command
CMD ["uv", "run", "nb-dt-import.py"]

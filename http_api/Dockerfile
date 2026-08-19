# Nebulock HTTP API container
#
# BUILD FROM THE REPO ROOT — this Dockerfile lives in http_api/ but its COPY
# paths are context-relative and it installs the athf package:
#
#     docker build -f http_api/Dockerfile -t cooey-nebulock:<ver> .
#
# It deliberately does NOT live at ./Dockerfile: upstream owns that path for the
# interactive CLI *test* container (gh + AWS CLI + bash). This is a different
# artifact — a long-running uvicorn service — so the two coexist rather than one
# silently overwriting the other on every upstream sync.
#
# Runs a FastAPI wrapper around the athf.core threat hunting managers on :8090
# so external services (maraudersMap, any other client) can create hunts,
# run agents, query ATT&CK coverage, etc. over plain JSON.
#
# Ships the full athf package + the http_api FastAPI server.
# Agent/LLM features require API keys to be passed as env vars at runtime:
#   ANTHROPIC_API_KEY / OPENAI_API_KEY / TAVILY_API_KEY

FROM python:3.11-slim AS base

# Non-interactive apt + stdout unbuffered for proper docker logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Minimal runtime deps: curl for healthcheck + build tools for scikit-learn wheels
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      gcc \
      g++ \
      libstdc++6 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/nebulock

# Dependencies FIRST, source second — the two are cached separately.
#
# The original order copied `athf/` before `pip install ".[all]"`, so editing a
# single line of source invalidated the install layer and rebuilt litellm,
# scikit-learn, mitreattack-python and the rest from scratch: ~8 minutes per
# iteration. The dependency list is still derived from pyproject.toml (never a
# hand-maintained copy that can drift), it just gets its own layer.
COPY pyproject.toml README.md MANIFEST.in ./
COPY http_api/requirements.txt ./http_api/requirements.txt
RUN pip install --upgrade pip setuptools wheel \
 && python -c "import tomllib; p = tomllib.load(open('pyproject.toml','rb'))['project']; \
print('\n'.join(p['dependencies'] + p['optional-dependencies']['all']))" > /tmp/reqs.txt \
 && pip install -r /tmp/reqs.txt -r http_api/requirements.txt

# Now the source. `--no-deps` because everything above is already resolved.
COPY athf ./athf
COPY http_api ./http_api
RUN pip install --no-deps .

# Create the default workspace path (can be mounted over at runtime)
RUN mkdir -p /workspace/hunts /workspace/research /workspace/investigations

ENV NEBULOCK_WORKSPACE=/workspace \
    NEBULOCK_API_PORT=8090 \
    PYTHONPATH=/opt/nebulock

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8090/health || exit 1

# Launch uvicorn serving the FastAPI app at http_api/server.py
CMD ["uvicorn", "server:app", \
     "--app-dir", "/opt/nebulock/http_api", \
     "--host", "0.0.0.0", \
     "--port", "8090", \
     "--log-level", "info"]

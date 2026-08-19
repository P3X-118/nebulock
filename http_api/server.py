"""
Nebulock HTTP API — FastAPI wrapper around athf.core managers.

Exposes the same operations that the MCP tools expose (hunt list/get/search/
new, research list/get/create, investigation list/search, agent hypothesis +
researcher, ATT&CK coverage, similar hunts) as a plain JSON REST API so the
maraudersMap Node API can proxy write operations here.

Ports:
    8090 (default, override with NEBULOCK_API_PORT)

Workspace:
    NEBULOCK_WORKSPACE env var, default /workspace.
    Expects subdirectories: hunts/, research/, investigations/

Auth:
    NEBULOCK_API_TOKEN env var. Clients send `X-API-Token: <token>` on EVERY
    request — reads included. The service REFUSES TO START without a token
    unless NEBULOCK_ALLOW_NO_AUTH=1 is set explicitly (local development).

    This is fail-closed by design. The previous behaviour ("if unset, no auth")
    meant a deployment that simply forgot the variable served every write
    endpoint — hunt creation, hunt mutation, LLM-key-backed agent runs — to
    anyone who could reach the port, with no signal that anything was wrong.
"""

import logging
import os
import secrets
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("nebulock-api")

WORKSPACE = Path(os.environ.get("NEBULOCK_WORKSPACE", "/workspace"))
API_TOKEN = os.environ.get("NEBULOCK_API_TOKEN", "")
PORT = int(os.environ.get("NEBULOCK_API_PORT", "8090"))
REDIS_URL = os.environ.get("NEBULOCK_REDIS_URL", "")

# --- Redis-backed LLM key store ------------------------------------------
#
# LLM API keys for the agent features live in Redis under the hash
# `nebulock:llm_keys`. The maraudersMap Node API writes them via an
# ADMIN_TOKEN-guarded route; we read them here and set os.environ before
# each agent invocation so athf's existing llm_provider picks them up.
#
# Startup fallback: if the hash doesn't exist yet, we seed it from whatever
# env vars were passed at container start (.env → docker-compose → os.environ)
# so existing deployments keep working.

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not REDIS_URL:
        return None
    try:
        import redis  # type: ignore
        _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=3)
        _redis_client.ping()
        logger.info("connected to redis for llm key store: %s", REDIS_URL.split("@")[-1])
    except Exception as exc:
        logger.warning("redis connection failed (%s) — falling back to process env vars", exc)
        _redis_client = None
    return _redis_client


# Map of logical provider name → the env var athf reads
LLM_ENV_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "tavily": "TAVILY_API_KEY",
}


def load_llm_keys_into_env() -> dict:
    """Pull LLM keys from the Redis hash (if configured) into os.environ.

    Returns a dict of {provider: bool} indicating which keys were applied.
    This is called at startup and at the top of every agent request, so key
    rotation via the UI takes effect on the very next agent call.
    """
    applied = {p: False for p in LLM_ENV_VARS}
    client = _get_redis()
    if client is None:
        # No Redis — fall back to whatever env vars were injected at start
        for provider, var in LLM_ENV_VARS.items():
            applied[provider] = bool(os.environ.get(var))
        return applied
    try:
        data = client.hgetall("nebulock:llm_keys") or {}
    except Exception as exc:
        logger.warning("redis hgetall failed: %s", exc)
        return applied
    for provider, var in LLM_ENV_VARS.items():
        val = data.get(f"{provider}_api_key") or data.get(provider) or ""
        if val:
            os.environ[var] = val
            applied[provider] = True
        elif os.environ.get(var):
            applied[provider] = True  # already set from .env
    # Optional model overrides
    for k in ("llm_provider", "llm_model"):
        v = data.get(k)
        if v:
            os.environ[f"ATHF_{k.upper()}"] = v
    return applied


def seed_keys_from_env_to_redis() -> None:
    """First-run migration: if Redis hash is empty but env vars are set,
    mirror them into Redis so the UI can display them as configured.
    """
    client = _get_redis()
    if client is None:
        return
    try:
        existing = client.hgetall("nebulock:llm_keys") or {}
    except Exception:
        return
    updates = {}
    for provider, var in LLM_ENV_VARS.items():
        field = f"{provider}_api_key"
        if not existing.get(field) and os.environ.get(var):
            updates[field] = os.environ[var]
    if updates:
        try:
            client.hset("nebulock:llm_keys", mapping=updates)
            logger.info("seeded %d llm keys from env into redis", len(updates))
        except Exception as exc:
            logger.warning("seed failed: %s", exc)

# Ensure required subdirectories exist so managers don't trip over missing paths
for sub in ("hunts", "research", "investigations"):
    (WORKSPACE / sub).mkdir(parents=True, exist_ok=True)

# --- Auth ------------------------------------------------------------------
#
# Applied ONCE as a router-level dependency, so every route on `api` is covered
# by construction. It used to be an opt-in per-route await, which produced two
# silent holes: the read endpoints simply never called it, and GET /hunts
# called it with a literal None (`_check_token(None if _ is None else None)`),
# so it returned 401 on every request once a token was configured — the list
# endpoint was unusable in exactly the mode you would deploy. A gate you have
# to remember to apply is a gate that eventually is not applied.

ALLOW_NO_AUTH = os.environ.get("NEBULOCK_ALLOW_NO_AUTH", "") == "1"

if not API_TOKEN and not ALLOW_NO_AUTH:
    raise SystemExit(
        "refusing to start: NEBULOCK_API_TOKEN is empty. This service can create "
        "hunts, mutate hunt files and spend LLM credits — it does not run "
        "unauthenticated. Set NEBULOCK_API_TOKEN, or set NEBULOCK_ALLOW_NO_AUTH=1 "
        "for local development."
    )
if not API_TOKEN:
    logger.warning("NEBULOCK_ALLOW_NO_AUTH=1 — serving UNAUTHENTICATED. "
                   "Never do this on a shared or published port.")


async def _check_token(x_api_token: Optional[str] = Header(None)) -> None:
    if not API_TOKEN:
        return
    # Constant-time: the token is a shared secret, and a plain `!=` turns this
    # endpoint into an oracle for guessing it.
    if not x_api_token or not secrets.compare_digest(x_api_token, API_TOKEN):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Token")


app = FastAPI(
    title="Nebulock HTTP API",
    version="0.2.0",
    description="HTTP wrapper around athf threat hunting core managers",
)

# Everything except /health hangs off this router. /health stays open because
# the container HEALTHCHECK curls it with no credentials; it reports booleans
# and paths only, never hunt content.
api = APIRouter(dependencies=[Depends(_check_token)])


@app.on_event("startup")
async def _startup() -> None:
    seed_keys_from_env_to_redis()
    load_llm_keys_into_env()


# --- Lazy manager accessors (imported at call time to avoid startup failures
# if athf dependencies change) --------------------------------------------

def _hunt_manager():
    from athf.core.hunt_manager import HuntManager
    return HuntManager(hunts_dir=WORKSPACE / "hunts")


def _research_manager():
    from athf.core.research_manager import ResearchManager
    return ResearchManager(research_dir=WORKSPACE / "research")


# --- Health + meta ---------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "workspace": str(WORKSPACE),
        "hunts_dir_exists": (WORKSPACE / "hunts").exists(),
        "research_dir_exists": (WORKSPACE / "research").exists(),
        "investigations_dir_exists": (WORKSPACE / "investigations").exists(),
        "auth_required": bool(API_TOKEN),
        "redis_configured": bool(REDIS_URL),
    }


# --- LLM key config --------------------------------------------------------

@api.get("/config/status")
async def config_status() -> dict:
    """Presence-only report of configured LLM keys.

    NEVER returns the plaintext values — only booleans. Used by the UI to
    show which providers are currently set up.
    """
    applied = load_llm_keys_into_env()
    # Also report which models are configured (overrideable via redis)
    return {
        "providers": applied,
        "llm_provider": os.environ.get("ATHF_LLM_PROVIDER") or None,
        "llm_model": os.environ.get("ATHF_LLM_MODEL") or None,
        "store": "redis" if _get_redis() is not None else "env",
    }


class ConfigTestRequest(BaseModel):
    provider: str  # "anthropic" | "openai" | "tavily"


@api.post("/config/test")
async def config_test(
    body: ConfigTestRequest,
) -> dict:
    """Run a minimal ping against whichever provider is configured.

    This is how the UI surfaces "Test" buttons. Guarded by the admin API
    token if NEBULOCK_API_TOKEN is set.
    """
    load_llm_keys_into_env()
    provider = (body.provider or "").lower().strip()

    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            return {"ok": False, "provider": provider, "error": "no anthropic key configured"}
        try:
            import anthropic  # type: ignore
            client = anthropic.Anthropic(api_key=key)
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=8,
                messages=[{"role": "user", "content": "ping"}],
            )
            return {"ok": True, "provider": provider, "model": msg.model if hasattr(msg, "model") else None}
        except Exception as exc:
            return {"ok": False, "provider": provider, "error": str(exc)[:200]}

    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            return {"ok": False, "provider": provider, "error": "no openai key configured"}
        try:
            from openai import OpenAI  # type: ignore
            client = OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=8,
                messages=[{"role": "user", "content": "ping"}],
            )
            return {"ok": True, "provider": provider, "model": resp.model}
        except Exception as exc:
            return {"ok": False, "provider": provider, "error": str(exc)[:200]}

    if provider == "tavily":
        key = os.environ.get("TAVILY_API_KEY", "")
        if not key:
            return {"ok": False, "provider": provider, "error": "no tavily key configured"}
        try:
            from tavily import TavilyClient  # type: ignore
            client = TavilyClient(api_key=key)
            # Cheapest operation: context search with tiny max_tokens
            client.search(query="test", max_results=1)
            return {"ok": True, "provider": provider}
        except Exception as exc:
            return {"ok": False, "provider": provider, "error": str(exc)[:200]}

    return {"ok": False, "provider": provider, "error": "unknown provider"}


# --- Hunt endpoints --------------------------------------------------------

@api.get("/hunts")
async def list_hunts(
    status: Optional[str] = None,
    tactic: Optional[str] = None,
    technique: Optional[str] = None,
    platform: Optional[str] = None,
    q: Optional[str] = None,
) -> JSONResponse:
    try:
        mgr = _hunt_manager()
        if q:
            hunts = mgr.search_hunts(q)
        else:
            hunts = mgr.list_hunts(status=status, tactic=tactic, technique=technique, platform=platform)
        return JSONResponse({"count": len(hunts), "hunts": hunts})
    except Exception as exc:
        logger.exception("list_hunts failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@api.get("/hunts/{hunt_id}")
async def get_hunt(hunt_id: str) -> JSONResponse:
    try:
        mgr = _hunt_manager()
        hunt = mgr.get_hunt(hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail=f"Hunt not found: {hunt_id}")
        # jsonable_encoder, not JSONResponse(hunt): the frontmatter comes back
        # from yaml.safe_load, so `date:` is a datetime.date and json.dumps
        # raises -> every hunt detail was a 500.
        return JSONResponse(jsonable_encoder(hunt))
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_hunt failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@api.get("/hunts-stats")
async def hunt_stats() -> JSONResponse:
    try:
        mgr = _hunt_manager()
        return JSONResponse(mgr.calculate_stats())
    except Exception as exc:
        logger.exception("hunt_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@api.get("/coverage")
async def hunt_coverage() -> JSONResponse:
    try:
        mgr = _hunt_manager()
        return JSONResponse(mgr.calculate_attack_coverage())
    except Exception as exc:
        logger.exception("hunt_coverage failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class HuntNewRequest(BaseModel):
    title: str
    technique: str
    tactic: Optional[str] = None
    platform: Optional[str] = None
    data_source: Optional[str] = None
    hypothesis: Optional[str] = None
    threat_context: Optional[str] = None
    actor: Optional[str] = None
    behavior: Optional[str] = None
    location: Optional[str] = None
    evidence: Optional[str] = None
    hunter: str = Field(default="Marauder's Map")
    research_id: Optional[str] = None


@api.post("/hunts")
async def create_hunt(
    body: HuntNewRequest,
) -> JSONResponse:
    try:
        from datetime import datetime
        from athf.core.hunt_manager import HuntManager
        from athf.core.template_engine import render_hunt_template

        mgr = HuntManager(hunts_dir=WORKSPACE / "hunts")
        hunt_id = mgr.get_next_hunt_id()

        content = render_hunt_template(
            hunt_id=hunt_id,
            title=body.title,
            technique=body.technique,
            tactics=[body.tactic] if body.tactic else None,
            platform=[body.platform] if body.platform else None,
            data_sources=[body.data_source] if body.data_source else None,
            hypothesis=body.hypothesis,
            threat_context=body.threat_context,
            actor=body.actor,
            behavior=body.behavior,
            location=body.location,
            evidence=body.evidence,
            hunter=body.hunter,
            spawned_from=body.research_id,
        )

        now = datetime.now()
        quarter = f"Q{(now.month - 1) // 3 + 1}"
        hunt_dir = WORKSPACE / "hunts" / "production" / str(now.year) / quarter
        hunt_dir.mkdir(parents=True, exist_ok=True)
        hunt_file = hunt_dir / f"{hunt_id}.md"

        try:
            with open(str(hunt_file), "x", encoding="utf-8") as fh:
                fh.write(content)
        except FileExistsError:
            raise HTTPException(status_code=409, detail=f"Hunt file already exists: {hunt_file}")

        return JSONResponse({
            "hunt_id": hunt_id,
            "file_path": str(hunt_file),
            "title": body.title,
            "technique": body.technique,
        }, status_code=201)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("create_hunt failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class HuntUpdateRequest(BaseModel):
    # Partial update — any fields provided are spliced into the existing file
    status: Optional[str] = None
    findings_count: Optional[int] = None
    true_positives: Optional[int] = None
    false_positives: Optional[int] = None
    learn: Optional[str] = None
    observe: Optional[str] = None
    check: Optional[str] = None
    keep: Optional[str] = None
    tags: Optional[list[str]] = None


@api.put("/hunts/{hunt_id}")
async def update_hunt(
    hunt_id: str,
    body: HuntUpdateRequest,
) -> JSONResponse:
    try:
        mgr = _hunt_manager()
        hunt_file = mgr.find_hunt_file(hunt_id)
        if hunt_file is None:
            raise HTTPException(status_code=404, detail=f"Hunt not found: {hunt_id}")

        original = hunt_file.read_text(encoding="utf-8")
        # Light in-place update: rewrite the frontmatter keys that are set,
        # then rewrite LOCK section bodies that are set. Keep everything else.
        new_content = _apply_hunt_patch(original, body)
        hunt_file.write_text(new_content, encoding="utf-8")
        return JSONResponse({"hunt_id": hunt_id, "file_path": str(hunt_file), "updated": True})
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("update_hunt failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _apply_hunt_patch(content: str, patch: "HuntUpdateRequest") -> str:
    """Mutate a hunt markdown file in place.

    Updates frontmatter scalar keys (status/findings_count/true_positives/
    false_positives/tags) and LOCK section bodies (learn/observe/check/keep).
    Preserves all other content verbatim.
    """
    import re

    # Split frontmatter
    fm_match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
    if not fm_match:
        body = content
        fm_lines: list[str] = []
        rest = content
    else:
        fm_lines = fm_match.group(1).splitlines()
        rest = content[fm_match.end():]

    def _set_fm(lines: list[str], key: str, value: Any) -> list[str]:
        if value is None:
            return lines
        if isinstance(value, list):
            rendered = "[" + ", ".join(str(v) for v in value) + "]"
        else:
            rendered = str(value)
        pattern = re.compile(rf"^{re.escape(key)}:\s*.*$")
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = f"{key}: {rendered}"
                return lines
        lines.append(f"{key}: {rendered}")
        return lines

    fm_lines = _set_fm(fm_lines, "status", patch.status)
    fm_lines = _set_fm(fm_lines, "findings_count", patch.findings_count)
    fm_lines = _set_fm(fm_lines, "true_positives", patch.true_positives)
    fm_lines = _set_fm(fm_lines, "false_positives", patch.false_positives)
    fm_lines = _set_fm(fm_lines, "tags", patch.tags)

    def _replace_section(body: str, heading: str, new_body: Optional[str]) -> str:
        if new_body is None:
            return body
        # Match "## HEADING" then anything until the next "## " or EOF
        pattern = re.compile(rf"(## {re.escape(heading)}\b.*?\n)(.*?)(?=\n## |\Z)", re.DOTALL | re.IGNORECASE)
        if pattern.search(body):
            return pattern.sub(lambda m: m.group(1) + new_body.rstrip() + "\n", body)
        # Section missing — append at the end
        return body.rstrip() + f"\n\n## {heading}\n\n{new_body.rstrip()}\n"

    rest = _replace_section(rest, "LEARN", patch.learn)
    rest = _replace_section(rest, "OBSERVE", patch.observe)
    rest = _replace_section(rest, "CHECK", patch.check)
    rest = _replace_section(rest, "KEEP", patch.keep)

    if fm_lines:
        return "---\n" + "\n".join(fm_lines) + "\n---\n" + rest
    return rest


# --- Research endpoints ----------------------------------------------------

@api.get("/research")
async def list_research(
    status: Optional[str] = None,
    depth: Optional[str] = None,
    technique: Optional[str] = None,
) -> JSONResponse:
    try:
        mgr = _research_manager()
        docs = mgr.list_research(status=status, technique=technique)
        # `depth` is not a ResearchManager filter (passing it raised TypeError
        # on every request); it lives in the document frontmatter, so filter here.
        if depth:
            docs = [d for d in docs if (d.get("depth") or "") == depth]
        return JSONResponse(jsonable_encoder({"count": len(docs), "research": docs}))
    except Exception as exc:
        logger.exception("list_research failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@api.get("/research/{research_id}")
async def get_research(research_id: str) -> JSONResponse:
    try:
        mgr = _research_manager()
        doc = mgr.get_research(research_id)
        if doc is None:
            raise HTTPException(status_code=404, detail=f"Research not found: {research_id}")
        return JSONResponse(jsonable_encoder(doc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_research failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class ResearchNewRequest(BaseModel):
    topic: str
    content: str
    technique: Optional[str] = None
    depth: str = "basic"
    title: Optional[str] = None


@api.post("/research")
async def create_research(
    body: ResearchNewRequest,
) -> JSONResponse:
    try:
        mgr = _research_manager()
        rid = mgr.get_next_research_id()
        frontmatter = {
            "research_id": rid,
            "title": body.title or f"{body.topic} Research",
            "topic": body.topic,
            "technique": body.technique or "",
            "depth": body.depth,
            "status": "draft",
        }
        file_path = mgr.create_research_file(
            research_id=rid, topic=body.topic, content=body.content, frontmatter=frontmatter
        )
        return JSONResponse({"research_id": rid, "file_path": str(file_path)}, status_code=201)
    except Exception as exc:
        logger.exception("create_research failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# --- Similar hunts ---------------------------------------------------------

@api.get("/similar")
async def similar(query: str, limit: int = 5) -> JSONResponse:
    try:
        mgr = _hunt_manager()
        results = mgr.search_hunts(query)[:limit]
        return JSONResponse({"count": len(results), "results": results})
    except Exception as exc:
        logger.exception("similar failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# --- Agent endpoints -------------------------------------------------------

class HypothesisRequest(BaseModel):
    threat_intel: str
    research_id: Optional[str] = None
    use_llm: bool = True


@api.post("/agent/hypothesis")
async def agent_hypothesis(
    body: HypothesisRequest,
) -> JSONResponse:
    # Pick up any key rotations since the last call
    load_llm_keys_into_env()
    try:
        from athf.agents.llm.hypothesis_generator import (
            HypothesisGeneratorAgent,
            HypothesisGenerationInput,
        )
        from athf.core.hunt_manager import HuntManager
        from athf.core.research_manager import ResearchManager

        research = None
        if body.research_id:
            rm = ResearchManager(research_dir=WORKSPACE / "research")
            doc = rm.get_research(body.research_id)
            if doc:
                research = rm.extract_research_context(doc)

        manager = HuntManager(hunts_dir=WORKSPACE / "hunts")
        past_hunts = manager.list_hunts()

        env_file = WORKSPACE / "environment.md"
        environment = {"environment_md": env_file.read_text(encoding="utf-8")} if env_file.exists() else {}

        agent = HypothesisGeneratorAgent(llm_enabled=body.use_llm)
        input_data = HypothesisGenerationInput(
            threat_intel=body.threat_intel,
            past_hunts=past_hunts,
            environment=environment,
            research=research,
        )
        result = agent.execute(input_data)
        if not result.success:
            raise HTTPException(status_code=500, detail=result.error or "hypothesis generation failed")
        output = result.data
        if output is None:
            raise HTTPException(status_code=500, detail="no output from hypothesis generator")

        return JSONResponse({
            "hypothesis": output.hypothesis,
            "mitre_techniques": output.mitre_techniques,
            "data_sources": output.data_sources,
            "justification": output.justification,
            "metadata": result.metadata,
        })
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("agent_hypothesis failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class ResearcherRequest(BaseModel):
    topic: str
    technique: Optional[str] = None
    depth: str = "advanced"
    use_web_search: bool = True
    use_llm: bool = True


@api.post("/agent/researcher")
async def agent_researcher(
    body: ResearcherRequest,
) -> JSONResponse:
    load_llm_keys_into_env()
    try:
        from athf.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput
        from athf.core.research_manager import ResearchManager

        tavily_key = os.environ.get("TAVILY_API_KEY") if body.use_web_search else None

        agent = HuntResearcherAgent(llm_enabled=body.use_llm, tavily_api_key=tavily_key)
        input_data = ResearchInput(
            topic=body.topic,
            mitre_technique=body.technique,
            depth=body.depth,
            web_search_enabled=body.use_web_search,
        )
        result = agent.execute(input_data)
        if not result.success:
            raise HTTPException(status_code=500, detail=result.error or "research failed")
        output = result.data
        if output is None:
            raise HTTPException(status_code=500, detail="no output from researcher")

        report_parts = [
            f"# {body.topic} Research\n",
            f"## System Research\n{output.system_research.summary}\n",
            f"## Adversary Tradecraft\n{output.adversary_tradecraft.summary}\n",
            f"## Telemetry Mapping\n{output.telemetry_mapping.summary}\n",
            f"## Related Work\n{output.related_work.summary}\n",
            f"## Synthesis\n{output.synthesis.summary}\n",
        ]
        if output.recommended_hypothesis:
            report_parts.append(f"## Recommended Hypothesis\n{output.recommended_hypothesis}\n")
        full_report = "\n".join(report_parts)

        rm = ResearchManager(research_dir=WORKSPACE / "research")
        rid = getattr(output, "research_id", None) or rm.get_next_research_id()
        frontmatter = {
            "research_id": rid,
            "title": f"{body.topic} Research",
            "topic": body.topic,
            "technique": body.technique or "",
            "depth": body.depth,
            "status": "completed",
        }
        file_path = rm.create_research_file(
            research_id=rid, topic=body.topic, content=full_report, frontmatter=frontmatter
        )

        return JSONResponse({
            "research_id": rid,
            "file_path": str(file_path),
            "topic": body.topic,
            "depth": body.depth,
            "recommended_hypothesis": output.recommended_hypothesis,
            "gaps_identified": output.gaps_identified,
            "metadata": result.metadata,
        })
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("agent_researcher failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


app.include_router(api)


# --- Global exception handler ---------------------------------------------

@app.exception_handler(Exception)
async def unhandled_error(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled error")
    return JSONResponse({"error": str(exc)}, status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, log_level="info")

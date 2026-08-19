"""Render hunt templates with metadata."""

from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml
from jinja2 import Template


def yaml_scalar(value) -> str:
    """Render a value as a SAFE YAML scalar for the frontmatter block.

    Implemented by asking PyYAML to emit it, rather than by hand-written
    quoting rules. Hand-rolled rules kept losing to edge cases a fuzzer found in
    seconds: `0x1f` round-trips as the integer 31, a form feed is rejected even
    inside double quotes, and a literal newline in a double-quoted scalar folds
    to a space. The emitter already knows every one of those rules, and it is
    the same library that will parse the file back.

    Written in response to a real corruption: a hunt created through the HTTP
    API with the title `SCAN: 198.51.100.7` rendered as

        title: SCAN: 198.51.100.7

    which is not valid YAML ("mapping values are not allowed here"). The file
    then failed to parse, so `list_hunts` silently skipped it (it swallows per
    file exceptions), so `get_next_hunt_id` never saw its id — and handed the
    SAME id out to the next hunt. Two files, one hunt_id, one of them invisible.

    A colon is only the most likely trigger; a leading '#', '&', '*', '!', '%',
    '@', '[', '{', '-' or a quote does the same, as does a value YAML would
    coerce to a non-string (`true`, `null`, `1.0`). Quote whenever the plain
    form is not unambiguously a string.
    """
    s = "" if value is None else str(value)
    # Emit as a one-line mapping and take the value back off. width is set huge
    # so the emitter never line-wraps (a wrapped scalar would break the single
    # frontmatter line), and default_flow_style keeps it inline.
    dumped = yaml.safe_dump({"v": s}, default_flow_style=False, allow_unicode=True,
                            width=10 ** 9, sort_keys=False)
    out = dumped[len("v:"):].strip("\n")
    if out.endswith("\n..."):                     # document-end marker, if any
        out = out[: -len("\n...")]
    return out.strip()


def yaml_flow_list(items) -> str:
    """Render a list as a YAML flow sequence with every item safely scalared.

    Empty/None entries are dropped rather than rendered as `""` — a blank
    platform or data source is absence, not a value.
    """
    kept = [i for i in (items or []) if i is not None and str(i).strip()]
    if not kept:
        return "[]"
    return "[" + ", ".join(yaml_scalar(i) for i in kept) + "]"

# Default bundled template - used when no custom template exists
HUNT_TEMPLATE = """---
hunt_id: {{ hunt_id }}
title: {{ title_yaml }}
status: {{ status }}
date: {{ date }}
hunter: {{ hunter_yaml }}
platform: {{ platform_yaml }}
tactics: {{ tactics_yaml }}
techniques: {{ techniques_yaml }}
data_sources: {{ data_sources_yaml }}
related_hunts: []
{% if spawned_from %}spawned_from: {{ spawned_from }}
{% endif %}{% if hypothesis_duration_minutes %}hypothesis_duration_minutes: {{ hypothesis_duration_minutes }}
{% endif %}findings_count: 0
true_positives: 0
false_positives: 0
customer_deliverables: []
tags: {{ tags }}
---

# {{ hunt_id }}: {{ title }}

**Hunt Metadata**

- **Date:** {{ date }}
- **Hunter:** {{ hunter }}
- **Status:** {{ status }}
- **MITRE ATT&CK:** {{ techniques[0] if techniques else '[Primary Technique]' }}

---

## LEARN: Prepare the Hunt

### Hypothesis Statement

{{ hypothesis if hypothesis else '[What behavior are you looking for? What will you observe if the hypothesis is true?]' }}

### Threat Context

{{ threat_context if threat_context else '[What threat actor/malware/TTP motivates this hunt?]' }}

### ABLE Scoping

| **Field**   | **Your Input** |
|-------------|----------------|
| **Actor** *(Optional)* | {{ actor if actor else '[Threat actor or malware family]' }} |
| **Behavior** | {{ behavior if behavior else '[TTP or behavior pattern]' }} |
| **Location** | {{ location if location else '[Systems, networks, or environments to hunt]' }} |
| **Evidence** | {{ evidence if evidence else '[Data sources and key fields to examine]' }} |

### Threat Intel & Research

- **MITRE ATT&CK Techniques:** {{ ', '.join(techniques) if techniques else '[List relevant techniques]' }}
- **CTI Sources & References:** [Links to reports, blogs, etc.]
{% if spawned_from %}- **Research Document:** See [{{ spawned_from }}](../research/{{ spawned_from }}.md) for detailed pre-hunt research
{% endif %}

### Related Tickets

| **Team** | **Ticket/Details** |
|----------|-------------------|
| **SOC/IR** | [Ticket numbers or N/A] |

---

## OBSERVE: Expected Behaviors

### What Normal Looks Like

[Describe legitimate activity that should not trigger alerts]

### What Suspicious Looks Like

[Describe adversary behavior patterns to hunt for]

### Expected Observables

- **Processes:** [Process names, command lines]
- **Network:** [Connections, protocols, domains]
- **Files:** [File paths, extensions, sizes]
- **Registry:** [Registry keys if applicable]
- **Authentication:** [Login patterns if applicable]

---

## CHECK: Execute & Analyze

### Data Source Information

- **Index/Data Source:** {{ data_sources[0] if data_sources else '[SIEM index or data source]' }}
- **Time Range:** [Date range for hunt]
- **Events Analyzed:** [Approximate count]
- **Data Quality:** [Assessment of data completeness]

### Hunting Queries

#### Initial Query

```
[Your initial query]
```

**Query Notes:**
- [What did this query return?]
- [What worked? What didn't?]

### Query Performance

**What Worked Well:**
- [Effective filters or techniques]

**What Didn't Work:**
- [Challenges or limitations]

**Iterations Made:**
- [Document query evolution]

---

## KEEP: Findings & Response

### Executive Summary

[Concise summary of hunt results and key findings]

### Findings

| **Finding** | **Ticket** | **Description** |
|-------------|-----------|-----------------|
| [Type] | [Ticket] | [Description] |

**True Positives:** 0
**False Positives:** 0

### Lessons Learned

**What Worked Well:**
- [Successes]

**What Could Be Improved:**
- [Areas for improvement]

**Telemetry Gaps Identified:**
- [Missing data sources or visibility gaps]

### Follow-up Actions

- [ ] [Action item 1]
- [ ] [Action item 2]

---

**Hunt Completed:** [Date]
**Next Review:** [Date for recurring hunt if applicable]
"""


def _load_hunt_template() -> str:
    """Load hunt template, preferring workspace custom template over bundled default.

    Checks for a Jinja2 template at ./templates/HUNT_TEMPLATE.j2 first.
    Falls back to the bundled HUNT_TEMPLATE constant.

    Returns:
        Jinja2 template string
    """
    custom_template = Path("templates") / "HUNT_TEMPLATE.j2"
    if custom_template.exists():
        try:
            content = custom_template.read_text(encoding="utf-8")
            # Basic sanity check: must contain Jinja2 syntax
            if "{{" in content and "}}" in content:
                return content
        except (OSError, UnicodeDecodeError):
            pass  # Fall through to default
    return HUNT_TEMPLATE


def render_hunt_template(
    hunt_id: str,
    title: str,
    technique: Optional[str] = None,
    tactics: Optional[list] = None,
    platform: Optional[list] = None,
    data_sources: Optional[list] = None,
    hunter: str = "[Your Name]",
    hypothesis: Optional[str] = None,
    threat_context: Optional[str] = None,
    actor: Optional[str] = None,
    behavior: Optional[str] = None,
    location: Optional[str] = None,
    evidence: Optional[str] = None,
    spawned_from: Optional[str] = None,
    hypothesis_duration_minutes: Optional[float] = None,
) -> str:
    """Render a hunt template with provided metadata.

    Args:
        hunt_id: Hunt identifier (e.g., H-0001)
        title: Hunt title
        technique: Primary MITRE technique (e.g., T1003.001)
        tactics: List of MITRE tactics
        platform: List of platforms (Windows, Linux, macOS, Cloud)
        data_sources: List of data sources
        hunter: Hunter name
        hypothesis: Hypothesis statement
        threat_context: Threat context description
        actor: Threat actor (for ABLE)
        behavior: Behavior description (for ABLE)
        location: Location/scope (for ABLE)
        evidence: Evidence description (for ABLE)
        spawned_from: Research document ID (e.g., R-0001) that this hunt is based on
        hypothesis_duration_minutes: Time spent generating hypothesis (from athf agent run)

    Returns:
        Rendered hunt markdown content
    """
    # Build techniques list
    techniques_list = [technique] if technique else []

    # The frontmatter block gets the *_yaml strings (each item quoted as needed);
    # the markdown BODY gets the real lists, because it does `techniques[0]`,
    # `', '.join(techniques)` and `data_sources[0]`. Passing a formatted string
    # into those turned the body into `[, T, 1, 5, 9, 5, ...]` — one character
    # per list element. (`data_sources` was already a string upstream, so that
    # line rendered a bare `[` before this change too.)
    tags_str = "[]"

    template = Template(_load_hunt_template())

    return str(template.render(
        hunt_id=hunt_id,
        # `title`/`hunter` stay raw for the markdown H1 and the metadata prose;
        # the *_yaml pair is what the frontmatter block uses. Both are passed so
        # a user's custom template written against the old `{{ title }}` name
        # still renders (unquoted, as it did before) instead of going blank.
        title=title,
        title_yaml=yaml_scalar(title),
        status="planning",
        date=datetime.now().strftime("%Y-%m-%d"),
        hunter=hunter,
        hunter_yaml=yaml_scalar(hunter),
        platform=platform or [],
        platform_yaml=yaml_flow_list(platform),
        tactics=tactics or [],
        tactics_yaml=yaml_flow_list(tactics),
        techniques=techniques_list,
        techniques_yaml=yaml_flow_list(techniques_list),
        data_sources=data_sources or [],
        data_sources_yaml=yaml_flow_list(data_sources),
        tags=tags_str,
        hypothesis=hypothesis,
        threat_context=threat_context,
        actor=actor,
        behavior=behavior,
        location=location,
        evidence=evidence,
        spawned_from=spawned_from,
        hypothesis_duration_minutes=hypothesis_duration_minutes,
    ))

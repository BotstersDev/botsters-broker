# Actuator Selection Design

**Author:** FootGun (from Peter's design)  
**Date:** 2026-02-25  
**Status:** Implemented (broker patched)

## Principle

**Selection, not routing.** An agent has one selected actuator for command execution, period. There is no capability-based routing. All commands go to the selected actuator.

## The `selected_actuator_id` Field

Every agent has a `selected_actuator_id` column (nullable). This is the **single source of truth** for which actuator handles the agent's commands.

- **NULL** — no actuator selected; commands will fail unless implicit selection applies
- **Set** — all commands go to this actuator

## Selection Logic (`resolveActuatorForAgent`)

```
1. Explicit override (caller passes actuator_id)
   → Use it if valid and assigned. If invalid, return null. No fallthrough.

2. Persisted selection (agents.selected_actuator_id)
   → Use it if valid. If invalid, return null. No fallthrough.

3. Implicit auto-selection
   → ONLY when selected_actuator_id is NULL
   → Count non-brain actuators assigned to this agent
   → If exactly 1: set selected_actuator_id to that actuator, return it
   → Otherwise: return null

4. Null
   → Agent must explicitly select via POST /v1/actuator/select
```

## Brain-Type Actuators Are Never Candidates

Brain-type actuators (ego actuators) exist for push notifications back to the agent's gateway. They are **never** candidates for command execution. Step 3 filters them with `type != 'brain'`.

## What Was Removed

`findActuatorWithCapability` — a function that selected actuators by matching capabilities with `LIMIT 1` and no deterministic ordering. This violated the selection design by introducing implicit routing based on capability matching. It was dead code (not called from the main command path) but represented the wrong mental model. Deleted.

## DRY Policy

Per project policy: small codebases managed by one developer operate at **full DRY**. No duplicate selection logic. `resolveActuatorForAgent` is the single function for actuator selection. If you need to know which actuator an agent uses, call that function.

In larger codebases at high development velocity, consolidation happens at 3 instances. But this codebase is small — consolidate immediately.

## Explicit Selection API

When an agent has multiple non-brain actuators and no persisted selection, commands return an error directing the agent (or admin) to call:

```
POST /v1/actuator/select
{ "actuator_id": "<id>" }
```

This sets `selected_actuator_id` and all subsequent commands route there.

## Incident Context

On 2026-02-25, after a database wipe and actuator restoration, Síofra had two actuators assigned: an ego actuator (type="brain") and a VPS actuator (type="vps"). The auto-selection logic picked the ego actuator because it was the first one found, resulting in "Brain-mode actuator does not execute commands" errors. The fix was to exclude brain-type actuators from auto-selection candidates.

"""Kafka worker: debounces alerts per device, runs the pipeline, posts the
incident + proposal to the API.

    uv run python -m scanu_agents.worker
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import defaultdict

import httpx
from aiokafka import AIOKafkaConsumer

from .graphdb import Neo4jHttp
from .llm import OpenAILLM
from .pipeline import Pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("scanu.worker")

KAFKA = os.getenv("SCANU_KAFKA", "127.0.0.1:19092")
API = os.getenv("SCANU_API", "http://127.0.0.1:8000")
SERVICE_TOKEN = os.getenv("SCANU_SERVICE_TOKEN", "dev-service-token")
DEBOUNCE_S = float(os.getenv("SCANU_DEBOUNCE_S", "3"))


class Worker:
    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline
        self.buffers: dict[tuple[str, str], list[dict]] = defaultdict(list)
        self.timers: dict[tuple[str, str], asyncio.Task] = {}

    def add(self, alert: dict) -> None:
        key = (alert["tenant_id"], alert["device_id"])
        self.buffers[key].append(alert)
        if (t := self.timers.get(key)) and not t.done():
            t.cancel()
        self.timers[key] = asyncio.create_task(self._flush_later(key))

    async def _flush_later(self, key: tuple[str, str]) -> None:
        await asyncio.sleep(DEBOUNCE_S)
        alerts = self.buffers.pop(key, [])
        if alerts:
            await self.process(key[0], key[1], alerts)

    async def process(self, tenant: str, device: str, alerts: list[dict]) -> None:
        state = await self.pipeline.run(tenant, device, alerts)
        if not state.get("keep"):
            log.info("triage dropped %d alert(s) for %s: %s", len(alerts), device, state.get("triage"))
            return
        if state.get("violations"):
            log.warning("LLM tool violations (rejected): %s", state["violations"])
        body = {
            "tenant_id": tenant,
            "device_id": device,
            "alert_ids": [a["alert_id"] for a in alerts],
            "produced_by": state["produced_by"],
            "incident": state["incident"],
            "proposal": state["proposal"],
        }
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(f"{API}/internal/incidents", json=body, headers={"X-Scanu-Service-Token": SERVICE_TOKEN})
        if r.status_code != 200:
            log.error("API rejected incident: %s %s", r.status_code, r.text)
        else:
            log.info("incident %s → %s (%s)", state["incident"]["incident_id"], r.json(), state["incident"]["title"])


async def main() -> None:
    llm = OpenAILLM()
    log.info("LLM %s", "enabled" if llm.available() else "disabled (deterministic correlation)")
    worker = Worker(Pipeline(Neo4jHttp(), llm))
    while True:
        consumer = AIOKafkaConsumer("scanu.alerts", bootstrap_servers=KAFKA, group_id="scanu-agents", auto_offset_reset="earliest")
        try:
            await consumer.start()
            log.info("consuming scanu.alerts")
            async for m in consumer:
                try:
                    worker.add(json.loads(m.value))
                except Exception:  # noqa: BLE001
                    log.exception("bad alert message")
        except Exception:  # noqa: BLE001
            log.exception("consumer crashed; restarting")
            await asyncio.sleep(2)
        finally:
            await consumer.stop()


if __name__ == "__main__":
    asyncio.run(main())

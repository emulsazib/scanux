"""Kafka producer/consumers (Redpanda in dev)."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from .config import settings

log = logging.getLogger("scanu.bus")
T_COMMANDS = "scanu.commands"
T_ALERTS = "scanu.alerts"
T_RESULTS = "scanu.cmd-results"
T_SCANS = "scanu.scan-progress"
T_DEVICES = "scanu.device-events"

producer: AIOKafkaProducer | None = None


async def start_producer() -> None:
    global producer
    producer = AIOKafkaProducer(bootstrap_servers=settings.kafka, acks="all", enable_idempotence=True)
    await producer.start()


async def stop_producer() -> None:
    if producer:
        await producer.stop()


async def publish_command(tenant_id: str, device_id: str, envelope_b64: str) -> None:
    assert producer is not None
    msg = {"tenant_id": tenant_id, "device_id": device_id, "signed_command_b64": envelope_b64}
    await producer.send_and_wait(T_COMMANDS, json.dumps(msg).encode(), key=device_id.encode())


async def consume(topic: str, group: str, handler: Callable[[dict], Awaitable[None]]) -> None:
    """Runs forever; a failing message is logged and skipped (poison-pill safe)."""
    while True:
        consumer = AIOKafkaConsumer(topic, bootstrap_servers=settings.kafka, group_id=group, auto_offset_reset="earliest")
        try:
            await consumer.start()
            async for m in consumer:
                try:
                    await handler(json.loads(m.value))
                except Exception:  # noqa: BLE001
                    log.exception("handler failed for %s offset %s", topic, m.offset)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("consumer for %s crashed; restarting", topic)
            await asyncio.sleep(2)
        finally:
            await consumer.stop()

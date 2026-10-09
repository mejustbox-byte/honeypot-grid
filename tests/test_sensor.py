import asyncio
import json

import pytest

from honeypot_grid.sensor import Sensor


@pytest.mark.parametrize("service", ["http-mock", "ssh-mock"])
def test_loopback_sensor_never_logs_payload_or_credentials(service):
    async def exercise():
        events = []
        sensor = Sensor(service, "sensor-demo", events.append)
        server = await asyncio.start_server(sensor.handle, "127.0.0.1", 0, limit=1024)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            if service == "http-mock":
                writer.write(
                    b"GET /?token=canary-secret HTTP/1.1\r\nAuthorization: canary-password\r\n\r\n"
                )
                await writer.drain()
            async with asyncio.timeout(3):
                data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            assert b"canary" not in data
            assert data.startswith(b"HTTP/1.1 200" if service == "http-mock" else b"SSH-2.0-")
            assert len(events) == 1
            assert "canary" not in json.dumps(events)
            assert "source_ip" not in events[0]
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(exercise())


def test_sensor_event_budget_closes_without_processing():
    async def exercise():
        events = []
        sensor = Sensor("ssh-mock", "sensor-demo", events.append)
        sensor.events = 1000
        server = await asyncio.start_server(sensor.handle, "127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.sockets[0].getsockname()[1]
            )
            async with asyncio.timeout(3):
                assert await reader.read() == b""
            assert events == []
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(exercise())

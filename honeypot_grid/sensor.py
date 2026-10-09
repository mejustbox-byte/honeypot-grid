"""Bounded synthetic HTTP/SSH listener. No shell, auth, proxy or payload logging."""

import argparse
import asyncio
import json
import secrets
import time

from .policy import Rejected, identifier, integer


class Sensor:
    def __init__(self, service: str, sensor_id: str, emit=None):
        if service not in ("http-mock", "ssh-mock"):
            raise Rejected("unsupported sensor")
        self.service = service
        self.sensor_id = identifier(sensor_id)
        self.active = 0
        self.events = 0
        self.emit = emit or (lambda event: print(json.dumps(event), flush=True))

    async def handle(self, reader, writer):
        if self.active >= 16 or self.events >= 1000:
            writer.close()
            await writer.wait_closed()
            return
        self.active += 1
        self.events += 1
        try:
            self.emit(
                {
                    "schema_version": 1,
                    "sensor_id": self.sensor_id,
                    "timestamp": int(time.time()),
                    "service": self.service,
                    "category": "connection",
                }
            )
            if self.service == "ssh-mock":
                writer.write(b"SSH-2.0-HoneypotGrid_Lab\r\n")
            else:
                # Never read bodies, credentials, source identity or echo request bytes.
                async with asyncio.timeout(2):
                    await reader.read(1024)
                body = b"Synthetic lab service\n"
                writer.write(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
            async with asyncio.timeout(2):
                await writer.drain()
        except TimeoutError, ConnectionError:
            pass
        finally:
            self.active -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def serve(self, port=0, seconds=60):
        integer(port, 0, 65535)
        integer(seconds, 1, 3600)
        # Loopback is mandatory even inside no-network lab containers.
        server = await asyncio.start_server(self.handle, "127.0.0.1", port, limit=1024)
        try:
            async with server:
                await asyncio.sleep(seconds)
        finally:
            server.close()
            await server.wait_closed()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Synthetic loopback-only lab listener")
    parser.add_argument("--service", choices=("http-mock", "ssh-mock"), required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--sensor-id", default="sensor-" + secrets.token_hex(8))
    args = parser.parse_args(argv)
    try:
        asyncio.run(Sensor(args.service, args.sensor_id).serve(args.port, args.seconds))
        return 0
    except Rejected, OSError:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

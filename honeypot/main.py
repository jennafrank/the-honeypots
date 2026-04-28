"""Entry point for the SSH honeypot process."""

import asyncio
import logging
import os
import signal

from dotenv import load_dotenv

load_dotenv()

from .db import init_db
from .logger import setup_logging
from .server import start_server

logger = logging.getLogger(__name__)

HONEYPOT_PORT = int(os.environ.get("HONEYPOT_PORT", 22))
SSH_HOST_KEY = os.environ.get("SSH_HOST_KEY", "/data/ssh/host_key")


async def _main() -> None:
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    logger.info("Initialising honeypot (port %d)", HONEYPOT_PORT)

    init_db()

    server = await start_server(port=HONEYPOT_PORT, key_path=SSH_HOST_KEY)

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    logger.info("Honeypot running. CTRL-C to stop.")
    await stop.wait()

    logger.info("Shutting down…")
    server.close()
    await server.wait_closed()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()

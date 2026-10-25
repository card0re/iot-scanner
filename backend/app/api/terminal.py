import asyncio
import json
import logging
import telnetlib3

import asyncssh
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/terminal", tags=["terminal"])
log = logging.getLogger(__name__)

from app.wordlists import KNOWN_DEFAULTS


@router.get("/defaults/{device_type}")
def get_defaults(device_type: str):
    creds = KNOWN_DEFAULTS.get(device_type, KNOWN_DEFAULTS["unknown"])
    return {"device_type": device_type, "credentials": [{"username": u, "password": p} for u, p in creds]}


@router.websocket("/ssh/{host}/{port:int}")
async def ws_ssh(ws: WebSocket, host: str, port: int):
    await ws.accept()
    try:
        auth = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=30))
        username = auth.get("username", "root")
        password = auth.get("password", "")
    except Exception as e:
        await ws.send_json({"type": "error", "data": f"Auth timeout: {e}"})
        await ws.close()
        return

    await ws.send_json({"type": "status", "data": f"Connecting SSH to {host}:{port} as {username}..."})

    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host, port,
                username=username,
                password=password,
                known_hosts=None,
                connect_timeout=10,
            ),
            timeout=15,
        )
    except asyncssh.PermissionDenied:
        await ws.send_json({"type": "error", "data": "Permission denied — wrong credentials"})
        await ws.close()
        return
    except asyncssh.DisconnectError as e:
        await ws.send_json({"type": "error", "data": f"SSH disconnect: {e}"})
        await ws.close()
        return
    except asyncio.TimeoutError:
        await ws.send_json({"type": "error", "data": "Connection timeout"})
        await ws.close()
        return
    except Exception as e:
        await ws.send_json({"type": "error", "data": f"SSH error: {e}"})
        await ws.close()
        return

    try:
        chan, session = await conn.create_session(
            asyncssh.SSHClientProcess,
            term_type="xterm-256color",
            term_size=(120, 40),
        )
    except Exception as e:
        await ws.send_json({"type": "error", "data": f"Session error: {e}"})
        conn.close()
        await ws.close()
        return

    await ws.send_json({"type": "connected", "data": f"Connected to {host}:{port}"})

    async def read_ws():
        try:
            while True:
                msg = await ws.receive_text()
                parsed = json.loads(msg)
                if parsed.get("type") == "input":
                    session.stdin.write(parsed["data"])
                elif parsed.get("type") == "resize":
                    chan.change_terminal_size(
                        parsed.get("cols", 120), parsed.get("rows", 40)
                    )
        except (WebSocketDisconnect, Exception):
            pass

    async def ssh_loop():
        try:
            while not session.is_closing():
                try:
                    data = await asyncio.wait_for(session.stdout.read(4096), timeout=0.2)
                    if data:
                        await ws.send_json({"type": "output", "data": data})
                except asyncio.TimeoutError:
                    continue
        except Exception:
            pass
        await ws.send_json({"type": "disconnected", "data": "Session closed"})

    ws_task = asyncio.create_task(read_ws())
    ssh_task = asyncio.create_task(ssh_loop())

    done, pending = await asyncio.wait(
        [ws_task, ssh_task], return_when=asyncio.FIRST_COMPLETED
    )
    for t in pending:
        t.cancel()

    conn.close()
    try:
        await ws.close()
    except Exception:
        pass


@router.websocket("/telnet/{host}/{port:int}")
async def ws_telnet(ws: WebSocket, host: str, port: int):
    await ws.accept()
    await ws.send_json({"type": "status", "data": f"Connecting Telnet to {host}:{port}..."})

    reader = None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port),
            timeout=10,
        )
    except asyncio.TimeoutError:
        await ws.send_json({"type": "error", "data": "Connection timeout"})
        await ws.close()
        return
    except Exception as e:
        await ws.send_json({"type": "error", "data": f"Telnet error: {e}"})
        await ws.close()
        return

    await ws.send_json({"type": "connected", "data": f"Connected to {host}:{port}"})

    async def ws_read():
        try:
            while True:
                msg = await ws.receive_text()
                parsed = json.loads(msg)
                if parsed.get("type") == "input":
                    writer.write(parsed["data"])
        except (WebSocketDisconnect, Exception):
            pass

    async def telnet_loop():
        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=0.2)
                    if data:
                        await ws.send_json({"type": "output", "data": data})
                    if reader.at_eof():
                        break
                except asyncio.TimeoutError:
                    continue
        except Exception:
            pass
        await ws.send_json({"type": "disconnected", "data": "Session closed"})

    ws_task = asyncio.create_task(ws_read())
    telnet_task = asyncio.create_task(telnet_loop())

    done, pending = await asyncio.wait(
        [ws_task, telnet_task], return_when=asyncio.FIRST_COMPLETED
    )
    for t in pending:
        t.cancel()

    writer.close()
    try:
        await ws.close()
    except Exception:
        pass

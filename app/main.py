import hmac
import json
from hashlib import sha256
from os import getenv
from urllib.parse import parse_qsl

from fastapi import FastAPI, WebSocket, status
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.websockets import WebSocketDisconnect


app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])
TOKEN = getenv('BOT_TOKEN')


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        response = Response()
        response.delete_cookie('session', samesite=None)
        await websocket.send_denial_response(response)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()


def parse_init_data(token: str, raw_init_data: str):
    is_valid = validate_init_data(token, raw_init_data)
    if not is_valid:
        return False

    result = {}
    for key, value in parse_qsl(raw_init_data):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            result[key] = value
        else:
            result[key] = value
    return result


def validate_init_data(token, raw_init_data) -> str:
    try:
        parsed_data = dict(parse_qsl(raw_init_data))
    except ValueError:
        raise HTTPException(status.HTTP_403_FORBIDDEN)
    if "hash" not in parsed_data:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    init_data_hash = parsed_data.pop('hash')
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(parsed_data.items()))
    secret_key = hmac.new(key=b"WebAppData", msg=token.encode(), digestmod=sha256)

    is_valid = hmac.new(secret_key.digest(), data_check_string.encode(), sha256).hexdigest() == init_data_hash
    if not is_valid:
        raise HTTPException(status.HTTP_403_FORBIDDEN)
    return init_data_hash


@app.get("/")
async def get():
    return {'its': 'work'}


@app.get("/check/")
async def check(init_data: str, response: Response):
    session_hash = validate_init_data(TOKEN, init_data)
    response.set_cookie('session', session_hash, samesite=None)


@app.websocket("/ws/")
async def websocket_endpoint(websocket: WebSocket, init_data: str):
    validate_init_data(TOKEN, init_data)
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.send_personal_message(f"You wrote: {data}", websocket)
            await manager.broadcast("broadcast")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
        await manager.broadcast("disconnect")

import asyncio
from datetime import datetime
from enum import Enum
from typing import Callable, Awaitable, AsyncIterable

from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, UUID4


class EventType(str, Enum):
    NEW_MESSAGE = 'new_message'
    USER_CONNECTED = 'user_connected'
    USER_DISCONNECTED = 'user_disconnected'
    USER_JOINED = 'user_joined'


class Event(BaseModel):
    type: EventType


class NewMessageEvent(Event):
    type: EventType = Field(EventType.NEW_MESSAGE, const=True)
    message_id: UUID4
    from_user: str
    text: str
    sent_at: datetime


class UserConnectedEvent(Event):
    type: EventType = Field(EventType.USER_CONNECTED, const=True)
    username: str
    connected_at: datetime


class UserDisconnectedEvent(Event):
    type: EventType = Field(EventType.USER_DISCONNECTED, const=True)
    username: str
    disconnected_at: datetime


class UserJoinedEvent(Event):
    type: EventType = Field(EventType.USER_JOINED, const=True)
    username: str
    joined_at: datetime


OnDisconnect = Callable[["EventListener"], Awaitable]


class EventListener:

    def __init__(self, ws: WebSocket, events_source: AsyncIterable[Event], on_disconnect: OnDisconnect) -> None:
        self.ws = ws
        self.event_source = events_source
        self.on_disconnect = on_disconnect

    async def notify(self, event: Event) -> None:
        await self.ws.send_text(event.json())

    async def serve(self) -> None:
        listen = asyncio.create_task(self._listen())
        read = asyncio.create_task(self._read_event_source())
        await asyncio.wait([listen, read], return_when=asyncio.FIRST_COMPLETED)
        listen.cancel()
        read.cancel()

    async def _read_event_source(self):
        async for event in self.event_source:
            await self.notify(event)

    async def _listen(self) -> None:
        try:
            async for _ in self.ws.iter_text():
                pass
        except WebSocketDisconnect:
            await self.on_disconnect(self)

    @classmethod
    async def from_websocket(
            cls,
            ws: WebSocket,
            event_source: AsyncIterable[Event],
            on_disconnect: OnDisconnect,
    ) -> "EventListener":
        await ws.accept()
        return EventListener(ws, event_source, on_disconnect)

from asyncio import Queue
from datetime import datetime, timedelta
from typing import AsyncIterable

from fastapi import FastAPI, Depends, HTTPException, Query, WebSocket
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from pydantic import BaseModel

from listener import EventListener, Event, UserConnectedEvent, NewMessageEvent, UserDisconnectedEvent

app = FastAPI()


class MessageSend(BaseModel):
    from_user: str
    text: str


class Message(BaseModel):
    sent_at: datetime
    from_user: str
    text: str


class User(BaseModel):
    username: str
    token: str


class Room(BaseModel):
    creator: str
    name: str
    users: set[str]
    listeners: list[Queue[Event]]
    messages: list[Message]

    class Config:
        arbitrary_types_allowed = True


class RoomService:

    def __init__(self):
        self.rooms: dict[str, Room] = {}

    def get_room(self, room: str) -> Room:
        if room not in self.rooms:
            raise HTTPException(status_code=400, detail="Room does not exist")

        return self.rooms[room]

    def join(self, room_name: str, username: str) -> None:
        room = self.get_room(room_name)
        if username in room.users:
            raise HTTPException(status_code=400, detail="User already in room")
        room.users.add(username)

    def notify(self, room: str, event: Event) -> None:
        for q in self.get_room(room).listeners:
            q.put_nowait(event)

    async def get_events(self, room: str) -> AsyncIterable[Event]:
        async def wrapper(queue: Queue[Event]):
            while event := await queue.get():
                yield event

        q = Queue[Event]()
        room = self.get_room(room)
        room.listeners.append(q)

        return wrapper(q)

    async def send_message(self, room_name: str, message: MessageSend) -> Message:
        room = self.get_room(room_name)

        if message.from_user not in room.users:
            raise HTTPException(status_code=400, detail="User is not in the room")

        msg = Message(
            **message.dict(),
            sent_at=datetime.now(),
        )
        self.rooms[room_name].messages.append(msg)

        self.notify(room_name, event=NewMessageEvent(
            from_user=message.from_user,
            text=message.text,
            sent_at=datetime.now(),
        ))

        return msg

    def create_room(self, room: str, creator: str) -> Room:
        if room in self.rooms:
            raise HTTPException(status_code=400, detail="Room already exists")

        self.rooms[room] = Room(
            creator=creator,
            name=room,
            users=[creator],
            messages=[],
            listeners=[],
        )
        return self.rooms[room]


class UserService:

    def __init__(self, secret: str):
        self.users = set[str]()
        self.secret = secret

    def create_user(self, username: str) -> User:
        if username in self.users:
            raise HTTPException(status_code=400, detail="username already taken")

        now = datetime.now()
        print(now, now.timestamp())
        token = jwt.encode(
            key=self.secret,
            claims={
                'iat': int(now.timestamp()),
                'nbf': int(now.timestamp()),
                'exp': int((now + timedelta(weeks=2)).timestamp()),
                'sub': username,
            },
            algorithm=jwt.ALGORITHMS.HS256
        )
        return User(username=username, token=token)

    def delete_user(self, username: str) -> None:
        self.users.discard(username)

    def parse_token(self, token: str) -> User:
        try:
            claims = jwt.decode(token, self.secret, algorithms=[jwt.ALGORITHMS.HS256])
            return User(token=token, username=claims['sub'])
        except jwt.JWTError as e:
            raise HTTPException(status_code=401, detail=f"invalid token: {e.args[0]}")


room_service = RoomService()
user_service = UserService('qwerty')
auth_scheme = HTTPBearer()


def get_user(bearer: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> User:
    return user_service.parse_token(bearer.credentials)


@app.post('/sign-in')
async def auth(username: str = Query()) -> User:
    return user_service.create_user(username)


@app.post(
    '/rooms/{room}/',
    response_model=None,
    response_model_exclude_none=True,
    response_model_exclude_unset=True,
    status_code=201,
    summary="Creates a new room",
    description="Создает новую комнату, если ее название еще не занятно, в данном случае возвращает код 400."
)
async def create_room(room: str, user: User = Depends(get_user)) -> None:
    room_service.create_room(room, user.username)


@app.get(
    '/rooms/{room}/users/list',
    status_code=200,
    summary="Returns a list of users those were joined to the room"
)
async def get_room_users(room: str, user: User = Depends(get_user)) -> list[str]:
    return list(room_service.get_room(room).users)


@app.post(
    '/rooms/{room}/join/',
    response_model=None,
    response_model_exclude_none=True,
    response_model_exclude_unset=True,
    summary="Join current user to a room",
)
async def join(room: str, user: User = Depends(get_user)) -> None:
    room_service.join(room, user.username)


@app.post(
    '/rooms/{room}/messages/send',
    summary="Sends a message from current user to the room"
)
async def send_message(
        room: str,
        user: User = Depends(get_user),
        text: str = Query()
) -> Message:
    return await room_service.send_message(room, MessageSend(from_user=user.username, text=text))


@app.websocket('/rooms/{room}/events/listen')
async def listen_room_events(
        ws: WebSocket,
        room: str,
        user: User = Depends(get_user)
) -> None:
    try:
        event_source = await room_service.get_events(room)
    except HTTPException:
        await ws.close(400, 'room does not exist')
        return

    async def do_nothing():
        pass

    listener = await EventListener.from_websocket(ws, event_source, on_disconnect=do_nothing)
    room_service.notify(room, event=UserConnectedEvent(
        username=user.username,
        connected_at=datetime.now(),
    ))
    await listener.serve()
    room_service.notify(room, event=UserDisconnectedEvent(
        username=user.username,
        disconnected_at=datetime.now(),
    ))

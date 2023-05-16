import uuid
from asyncio import Queue
from datetime import datetime, timedelta
from typing import AsyncIterable, Annotated

from fastapi import FastAPI, Depends, HTTPException, Query, WebSocket, status, Form, Response
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, UUID4

from listener import EventListener, Event, UserConnectedEvent, NewMessageEvent, UserDisconnectedEvent, UserJoinedEvent

app = FastAPI()


class MessageSend(BaseModel):
    from_user: str
    text: str


class Message(BaseModel):
    message_id: UUID4
    sent_at: datetime
    from_user: str
    text: str


class UserInDb(BaseModel):
    username: str
    password_hash: str


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


class RoomGet(BaseModel):
    name: str
    members_count: int


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
        self.notify(room_name, UserJoinedEvent(
            username=username,
            joined_at=datetime.now()
        ))

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
            message_id=uuid.uuid4(),
            sent_at=datetime.now(),
        )
        self.rooms[room_name].messages.append(msg)

        self.notify(room_name, event=NewMessageEvent(
            message_id=msg.message_id,
            from_user=message.from_user,
            text=message.text,
            sent_at=datetime.now(),
        ))

        return msg

    def get_users_rooms(self, username: str) -> list[RoomGet]:
        result: list[RoomGet] = []
        for room in self.rooms.values():
            if username in room.users:
                result.append(RoomGet(
                    name=room.name,
                    members_count=len(room.users),
                ))

        return result

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
        self.users = dict[str, str]()
        self.secret = secret
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def authenticate_user(self, username: str) -> str:
        now = datetime.now()
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
        return token

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    def registrate_user(self, username, password):
        if username in self.users:
            raise HTTPException(
                status_code=400,
                detail=f"user with username '{username}' already exists"
            )
        hash_pass = user_service.get_password_hash(password)
        self.users[username] = hash_pass

    def find_user(self, username) -> UserInDb | None:
        if username in self.users:
            return UserInDb(username=username, password_hash=self.users[username])

    def check_pass(self, username: str, password: str) -> bool:
        user = self.find_user(username)
        if user is None:
            return False

        return self.verify_password(password, user.password_hash)

    def delete_user(self, username: str) -> None:
        del self.users[username]

    def parse_token(self, token: str) -> User:
        try:
            claims = jwt.decode(token, self.secret, algorithms=[jwt.ALGORITHMS.HS256])
            return User(token=token, username=claims['sub'])
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"invalid token: {e.args[0]}")


room_service = RoomService()
user_service = UserService('qwerty')
auth_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/sign-in",
)


def get_user(bearer: str = Depends(auth_scheme)) -> User:
    return user_service.parse_token(bearer)


def get_user_websocket(bearer: str = Query(alias='access_token')) -> User | None:
    try:
        return user_service.parse_token(bearer)
    except HTTPException:
        return None


@app.post(
    '/rooms/{room}/',
    response_model=None,
    status_code=201,
    summary="Creates a new room",
    description="Создает новую комнату, если ее название еще не занятно, в данном случае возвращает код 400."
)
async def create_room(room: str, user: User = Depends(get_user)):
    room_service.create_room(room, user.username)
    return Response(status_code=201)


@app.get(
    '/rooms/{room}/users/list',
    status_code=200,
    summary="Returns a list of users those were joined to the room",
    dependencies=[Depends(get_user)]
)
async def get_room_users(room: str) -> list[str]:
    return list(room_service.get_room(room).users)


@app.post(
    '/rooms/{room}/join/',
    response_model=None,
    summary="Join current user to a room",
    status_code=200,
)
async def join(room: str, user: User = Depends(get_user)):
    room_service.join(room, user.username)
    return Response(status_code=200)


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
        user: User = Depends(get_user_websocket),
) -> None:
    try:
        if user is None:
            await ws.close(1003, 'invalid token')
            return
        event_source = await room_service.get_events(room)
    except HTTPException:
        await ws.close(1003, 'room does not exist')
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


@app.get(
    "/rooms",
    response_model=list[RoomGet],
    status_code=200,
)
async def get_user_rooms(
        user: User = Depends(get_user),
) -> list[RoomGet]:
    return room_service.get_users_rooms(user.username)


@app.post("/auth/sign-in", status_code=200)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = user_service.check_pass(form_data.username, form_data.password)
    username = form_data.username
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = user_service.authenticate_user(username)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post(
    '/auth/sign-up',
    status_code=201,
    response_model=None,
)
async def auth(
        username: str = Form(description="username"),
        password: str = Form(description="password")
):
    user_service.registrate_user(username, password)
    return Response(status_code=201)

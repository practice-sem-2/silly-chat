# Silly-Chat

Простецкая реализация проека по ознакомительной практике на случай, если вдруг сроки начнут поджимать.

## Установка
```bash
docker pull burenotti/silly-chat:v0.1.0
docker run -dp 6969:80 burenotti/silly-chat:v0.1.0
```
После этого [докуха здесь](http://localhost:6969/docs) или [здесь](http://localhost:6969/redoc), 
там все можно интерактивно потыкать. Апи рут вот: http://localhost:6969.

## WebSocket
> Swagger не показывает websocket эндпоинты, поэтому работа с ними описана здесь.

`/rooms/{room}/events/listen` - путь к вебсокет соединению, которое стримит новые ивенты группы.

### Формат ивентов
Каждый ивент - это стркутура в формате json, которая имеет параметр `type`, идентифицирующий тип элемента.

##### Типы ивентов:
- `user_joined` - пользователь стал членом комнаты
- `user_connected` - пользователь в данный момент подключился и слушает события комнаты.
- `user_disconnected` - пользователь отключился от прослушки ивентов.
- `new_message` - в комнату отправлено сообщение

#### Payload ивентов:

- `user_joined`:
  - `username: string` - Имя присоединившегося пользователя
  - `joined_at: int` - Время, в которое произошло событие в формате unix timestamp
- `user_connected`:
  - `username: string` - Имя подключившегося пользователя
  - `connected_at: int` - Время, в которое произошло событие в формате unix timestamp
- `user_disconnected`:
  - `username: string` - Имя отключившегося пользователя
  - `disconnected_at: int` - Время, в которое произошло событие в формате unix timestamp
- `new_message`: 
  - `sent_at: int` - Время отправки сообщения в формате unix timestamp
  - `from_user: string` - Имя пользователя, отправившего сообщение
  - `text: string` - Текст сообщения

import asyncio
from aiohttp import web, ClientSession, WSMsgType

BACKEND = 'http://localhost:8000'
FRONTEND = 'http://localhost:5173'

def is_malicious(request, body: str) -> bool:
    suspicious_keywords = ["drop table", "<script>", "--", "or 1=1", "%3cscript%3e"]
    target_strings = [body, str(request.query_string), request.path]
    for key, value in request.headers.items():
        target_strings.append(f"{key}: {value}")
    for content in target_strings:
        lowered = content.lower()
        for bad in suspicious_keywords:
            if bad in lowered:
                return True
    return False

async def handler(request):
    body = await request.text()

    if is_malicious(request, body):
        return web.Response(status=403, text="Blocked by WAF")

    is_ws = (request.headers.get("connection", "").lower() == "upgrade" and
             request.headers.get("upgrade", "").lower() == "websocket")

    if is_ws or not request.path.startswith('/api'):
        target = FRONTEND + str(request.rel_url)
    else:
        target = BACKEND + str(request.rel_url)

    if is_ws:
        ws_server = web.WebSocketResponse()
        await ws_server.prepare(request)

        # Client-side WebSocket (Vite HMR), Vite sorun çıkarmasın diye
        async with ClientSession() as session:
            ws_client = await session.ws_connect(
                target,
                headers={k: v for k, v in request.headers.items() if k.lower() != 'host'},
                protocols=('vite-hmr',),
                compress=None
            )

            async def client_to_server():
                async for msg in ws_client:
                    if msg.type == WSMsgType.TEXT:
                        await ws_server.send_str(msg.data)
                    elif msg.type == WSMsgType.BINARY:
                        await ws_server.send_bytes(msg.data)
                    else:
                        break
                await ws_server.close()

            async def server_to_client():
                async for msg in ws_server:
                    if msg.type == WSMsgType.TEXT:
                        await ws_client.send_str(msg.data)
                    elif msg.type == WSMsgType.BINARY:
                        await ws_client.send_bytes(msg.data)
                    else:
                        break
                await ws_client.close()

            await asyncio.wait(
                [asyncio.create_task(client_to_server()),
                 asyncio.create_task(server_to_client())],
                return_when=asyncio.FIRST_COMPLETED
            )

        return ws_server

    async with ClientSession() as session:
        async with session.request(
            method=request.method,
            url=target,
            headers={k: v for k, v in request.headers.items() if k.lower() != 'host'},
            data=body
        ) as resp:
            raw = await resp.read()
            return web.Response(status=resp.status, headers=resp.headers, body=raw)

app = web.Application()
app.router.add_route('*', '/{tail:.*}', handler)

if __name__ == '__main__':
    web.run_app(app, port=80)

import aiohttp
from aiohttp import web

BACKEND = 'http://localhost:8001'

def is_malicious(request, body: str) -> bool:
    return any(bad in body.lower() for bad in ["drop table", "<script>", "--", "or 1=1"])

async def handler(request):
    try:
        body = await request.text()
        if is_malicious(request, body):
            return web.Response(status=403, text="Blocked by WAF")

        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=request.method,
                url=BACKEND + str(request.rel_url),
                headers={k: v for k, v in request.headers.items() if k.lower() != 'host'},
                data=body
            ) as resp:
                raw_body = await resp.read()
                return web.Response(
                    status=resp.status,
                    headers=resp.headers,
                    body=raw_body
                )
    except Exception as e:
        return web.Response(status=500, text=f"Proxy error: {e}")

app = web.Application()
app.router.add_route('*', '/{tail:.*}', handler)

if __name__ == '__main__':
    web.run_app(app, port=8080)

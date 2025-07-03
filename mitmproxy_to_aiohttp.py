from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    print(f"[mitmproxy] {flow.request.method} {flow.request.pretty_url}")

    if flow.request.method == "POST":
        body = flow.request.get_text()
        if "evil" in body.lower():
            flow.response = http.HTTPResponse.make(
                403, b"Blocked by mitmproxy", {"Content-Type": "text/plain"}
            )

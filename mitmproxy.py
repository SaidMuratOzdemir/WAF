from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if flow.request.method == "POST":
        print(f"[mitmproxy] POST {flow.request.pretty_url}")
        print(f"Body:\n{flow.request.get_text()}")

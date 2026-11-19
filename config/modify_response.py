"""Replace the lab witness in responses passing through mitmproxy."""


def response(flow):
    flow.response.content = flow.response.content.replace(
        b"PROJET_TLS_MOHAMED_FIRAS", b"MODIFIED_IN_TRANSIT"
    )

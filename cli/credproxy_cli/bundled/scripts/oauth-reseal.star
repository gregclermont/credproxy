# credproxy bundled script: oauth-reseal
#
# OAuth2 client-credentials re-seal, scripted -- the escape-hatch twin of the
# built-in oauth2-reseal scheme, and an authoring template for re-seal flows.
#
# on_request swaps the client_secret placeholder into the token request.
# on_response mints the returned access_token as a dynamic placeholder on the
# binding's api_hosts (params) and rewrites the body so the workspace receives
# the placeholder, not the real token. mint_into_json() owns the registration +
# body rewrite; the API hosts + target header come from the binding params
# (api_hosts, reseal_header).

def on_request():
    text = req_body()
    ph = placeholder()
    if not text or ph == None or ph not in text:
        return False
    req_set_body(text.replace(ph, secret()))
    return True

def on_response():
    if resp_status() != 200:
        return False
    tok = resp_json()
    if tok == None:
        return False
    access = tok.get("access_token")
    if access == None:
        return False
    mint_into_json("access_token", access, tok.get("expires_in", 3600))
    return True

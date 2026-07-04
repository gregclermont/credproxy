# A rule script (kind="rule"): scrub the `email` field from response bodies so
# the workspace never sees it. Wire it with:
#
#   credproxy workspace NAME rule add script --host api.github.com \
#       --path '/users/**' --script scrub-emails
#
# Rule scripts hold NO credential -- the secret/mint/crypto primitives are
# unavailable, and errors are reported in full (unlike injector scripts). This
# runs in the RESPONSE phase, after any re-seal, so it sees exactly what the
# workspace would.
def on_response():
    data = resp_json()
    if data == None:
        return
    # A single object (e.g. GET /users/octocat) or a list of them.
    if type(data) == "dict":
        _scrub(data)
    elif type(data) == "list":
        for item in data:
            if type(item) == "dict":
                _scrub(item)
    else:
        return
    resp_set_body(json_encode(data))


def _scrub(obj):
    for field in ("email", "notification_email"):
        if field in obj:
            obj[field] = None

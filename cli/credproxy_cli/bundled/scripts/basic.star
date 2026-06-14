# credproxy bundled script: basic
#
# A Starlark re-implementation of the built-in `basic` scheme -- an authoring
# template. HTTP Basic decode-and-swap: decode `Authorization: Basic`, swap the
# component equal to the placeholder (password by default, or username) for the
# real value, re-encode. The auth-scheme token is matched case-insensitively.

def on_request():
    header = param("header", "Authorization")
    value = req_header(header)
    ph = placeholder()
    if value == None or ph == None:
        return False
    if value[:6].lower() != "basic ":
        return False
    parts = b64decode(value[6:].strip()).split(":", 1)
    if len(parts) != 2:
        return False
    user = parts[0]
    pw = parts[1]
    if pw == ph:
        pw = secret()
    elif user == ph:
        user = secret()
    else:
        return False
    req_set_header(header, "Basic " + b64encode(user + ":" + pw))
    return True

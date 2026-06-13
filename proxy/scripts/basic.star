# Dogfood: the built-in `basic` scheme re-implemented as a Starlark script.
#
# HTTP Basic decode-and-swap: decode `Authorization: Basic`, swap the component
# equal to the placeholder (password by default, or username) for the real
# value, re-encode. The auth-scheme token is matched case-insensitively
# (RFC 7235). Behaviourally identical to proxy/schemes.py BasicScheme.

def on_request(ctx):
    header = param(ctx, "header", "Authorization")
    value = header_get(ctx, header)
    ph = placeholder(ctx)
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
        pw = secret(ctx)
    elif user == ph:
        user = secret(ctx)
    else:
        return False
    header_set(ctx, header, "Basic " + b64encode(user + ":" + pw))
    return True

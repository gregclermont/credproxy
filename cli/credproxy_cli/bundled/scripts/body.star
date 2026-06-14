# credproxy bundled script: body
#
# A Starlark re-implementation of the built-in `body` scheme -- an authoring
# template. Substring-swap the placeholder for the real value anywhere in the
# request body (OAuth2 client-credentials, key-in-body APIs).

def on_request():
    text = req_body()
    ph = placeholder()
    # `not text` matches the built-in: a None or empty body is a no-op (and
    # guards the `ph not in text` membership test below from a None text).
    if not text or ph == None:
        return False
    if ph not in text:
        return False
    req_set_body(text.replace(ph, secret()))
    return True

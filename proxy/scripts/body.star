# Dogfood: the built-in `body` scheme re-implemented as a Starlark script.
#
# Substring-swap the placeholder for the real value anywhere in the request
# body (OAuth2 client-credentials, key-in-body APIs). Behaviourally identical
# to proxy/schemes.py BodyScheme.

def on_request(ctx):
    text = body_text(ctx)
    ph = placeholder(ctx)
    # `not text` matches the built-in: a None or empty body is a no-op (and
    # guards the `ph not in text` membership test below from a None text).
    if not text or ph == None:
        return False
    if ph not in text:
        return False
    set_body_text(ctx, text.replace(ph, secret(ctx)))
    return True

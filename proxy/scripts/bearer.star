# Dogfood: the built-in `bearer` scheme re-implemented as a Starlark script.
#
# Substring-swap the placeholder for the real value inside a named header
# (default Authorization), leaving any "Bearer "/"token " prefix the client
# sent intact. Behaviourally identical to proxy/schemes.py BearerScheme; serves
# as an authoring example and the Python-vs-Starlark benchmark subject.

def on_request(ctx):
    header = param(ctx, "header", "Authorization")
    value = header_get(ctx, header)
    ph = placeholder(ctx)
    if value == None or ph == None:
        return False
    if ph not in value:
        return False
    header_set(ctx, header, value.replace(ph, secret(ctx)))
    return True

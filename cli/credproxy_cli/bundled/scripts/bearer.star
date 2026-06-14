# credproxy bundled script: bearer
#
# A Starlark re-implementation of the built-in `bearer` scheme -- an authoring
# template for scripted injectors (and the Python-vs-Starlark benchmark
# subject). Substring-swap the placeholder for the real value inside a named
# header (default Authorization), leaving any "Bearer "/"token " prefix intact.
#
# Reference it from a scripted injector:
#   scheme = "script"
#   script = "bearer"
#   api    = 1
#   family = "substitute"
#   slots  = ["value"]
#   [params]
#   header = "Authorization"

def on_request():
    header = param("header", "Authorization")
    value = req_header(header)
    ph = placeholder()
    if value == None or ph == None:
        return False
    if ph not in value:
        return False
    req_set_header(header, value.replace(ph, secret()))
    return True

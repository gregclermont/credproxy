# credproxy bundled script: jwt-bearer
#
# Self-signed JWT bearer assertion (RS256). Mints a fresh JWT on every request
# signed with the caller's RSA private key and sets Authorization: Bearer <jwt>.
# Covers GCP service-account self-signed JWTs ("direct service-account" auth),
# and any API that accepts RFC 7523 private-key JWT assertions.
#
# Slot: "private_key" (PEM-encoded PKCS#8 or PKCS#1 RSA private key).
# Because the slot is NOT named "value", you must name it explicitly when binding:
#
#   credproxy workspace NAME binding add \
#       --injector jwt-bearer \
#       --provider <provider> \
#       --secret private_key=<REF> \
#       --host api.example.com
#
# family = "sign": the private key never transits the wire.
#
# Placeholder (optional). With no placeholder the script mints on EVERY matching
# request (the classic from-scratch sign behavior). When the binding declares a
# placeholder, the workspace sends `Authorization: Bearer <placeholder>` and the
# script mints ONLY for requests that carry it -- giving per-request opt-in and
# letting the proxy run several identities on one host (the config `by_ph` layer
# disambiguates by which placeholder a request carries).
#
# Params (all optional, defaults shown in jwt-bearer.toml):
#   iss   - JWT issuer claim  (e.g. "my-service@project.iam.gserviceaccount.com")
#   aud   - JWT audience claim (e.g. "https://api.example.com/token")
#   ttl   - token lifetime in seconds (default "3600")
#   sub   - subject claim; omitted from JWT when empty (default "")

def on_request():
    # Optional placeholder gate: when set, only mint for requests carrying it.
    ph = placeholder()
    if ph != None:
        auth = req_header("Authorization")
        if auth == None or ph not in auth:
            return False

    iat = now()
    exp = iat + int(param("ttl", "3600"))

    claims = {"iss": param("iss", ""), "aud": param("aud", ""), "iat": iat, "exp": exp}
    sub = param("sub", "")
    if sub != "":
        claims["sub"] = sub

    # jwt_encode_sign owns the segment assembly (header.claims.signature),
    # base64url padding, and signing the right bytes -- the JWS footguns.
    jwt = jwt_encode_sign({"alg": "RS256", "typ": "JWT"}, claims, secret("private_key"))
    req_set_header("Authorization", "Bearer " + jwt)
    return True

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
# family = "sign": the private key never transits the wire; no placeholder swap.
# Params (all optional, defaults shown in jwt-bearer.toml):
#   iss   - JWT issuer claim  (e.g. "my-service@project.iam.gserviceaccount.com")
#   aud   - JWT audience claim (e.g. "https://api.example.com/token")
#   ttl   - token lifetime in seconds (default "3600")
#   sub   - subject claim; omitted from JWT when empty (default "")

def on_request(ctx):
    header_json = json_encode({"alg": "RS256", "typ": "JWT"})

    iat = now()
    exp = iat + int(param(ctx, "ttl", "3600"))

    claims = {"iss": param(ctx, "iss", ""), "aud": param(ctx, "aud", ""), "iat": iat, "exp": exp}
    sub = param(ctx, "sub", "")
    if sub != "":
        claims["sub"] = sub

    claims_json = json_encode(claims)

    signing_input = b64url_encode(header_json) + "." + b64url_encode(claims_json)
    sig = rs256_sign_b64url(secret(ctx, "private_key"), signing_input)
    jwt = signing_input + "." + sig

    header_set(ctx, "Authorization", "Bearer " + jwt)
    return True

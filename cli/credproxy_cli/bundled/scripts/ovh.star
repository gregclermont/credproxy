# credproxy bundled script: ovh
#
# OVH API request signing (sign family). Computes and injects the four headers
# required by the OVH API HTTP signature scheme:
#   X-Ovh-Application  <- app_key
#   X-Ovh-Consumer     <- consumer_key
#   X-Ovh-Timestamp    <- current unix timestamp
#   X-Ovh-Signature    <- "$1$" + SHA1(base string)
#
# The base string is:
#   app_secret + "+" + consumer_key + "+" + METHOD + "+" + full_url + "+" + body + "+" + ts
#
# Because this is a sign-family scheme there is no placeholder: the workspace
# sends a request with no OVH auth headers and the proxy adds them.
#
# Bind it with:
#   credproxy workspace NAME binding add --injector ovh --provider env \
#       --secret app_key=OVH_APP_KEY \
#       --secret app_secret=OVH_APP_SECRET \
#       --secret consumer_key=OVH_CONSUMER_KEY \
#       --host eu.api.ovh.com

def on_request(ctx):
    app_key = secret(ctx, "app_key")
    app_secret = secret(ctx, "app_secret")
    consumer_key = secret(ctx, "consumer_key")

    ts = str(now())
    body = body_text(ctx)
    if body == None:
        body = ""

    url = "https://" + host(ctx) + path(ctx)
    base = app_secret + "+" + consumer_key + "+" + method(ctx) + "+" + url + "+" + body + "+" + ts
    signature = "$1$" + hex_sha1(base)

    header_set(ctx, "X-Ovh-Application", app_key)
    header_set(ctx, "X-Ovh-Consumer", consumer_key)
    header_set(ctx, "X-Ovh-Timestamp", ts)
    header_set(ctx, "X-Ovh-Signature", signature)
    return True

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
# Placeholder (optional). With no placeholder the workspace sends a request with
# no OVH auth headers and the proxy adds them on EVERY matching request. When the
# binding declares a placeholder, the workspace presents it as `X-Ovh-Application`
# (a stand-in for the public app key) and the proxy signs ONLY requests carrying
# it -- giving per-request opt-in and letting several OVH identities share one
# host (the config `by_ph` layer disambiguates by the presented app-key). Either
# way the real app_key/secret/consumer_key never enter the workspace.
#
# Bind it with:
#   credproxy workspace NAME binding add --injector ovh --provider env \
#       --secret app_key=OVH_APP_KEY \
#       --secret app_secret=OVH_APP_SECRET \
#       --secret consumer_key=OVH_CONSUMER_KEY \
#       --host eu.api.ovh.com

def on_request():
    app_key = secret("app_key")
    app_secret = secret("app_secret")
    consumer_key = secret("consumer_key")

    # Optional placeholder gate: when set, only sign requests whose
    # X-Ovh-Application carries the placeholder app key.
    ph = placeholder()
    if ph != None:
        if req_header("X-Ovh-Application") != ph:
            return False

    ts = str(now())
    body = req_body()
    if body == None:
        body = ""

    url = "https://" + req_host() + req_path()
    base = app_secret + "+" + consumer_key + "+" + req_method() + "+" + url + "+" + body + "+" + ts
    signature = "$1$" + sha1_hex(base)

    req_set_header("X-Ovh-Application", app_key)
    req_set_header("X-Ovh-Consumer", consumer_key)
    req_set_header("X-Ovh-Timestamp", ts)
    req_set_header("X-Ovh-Signature", signature)
    return True

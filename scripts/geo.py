import requests
from transform import rebrand_config

def attach_country_codes(nodes: list):
    if not nodes:
        return

    unique_hosts = list({node["host"] for node in nodes if node.get("host")})
    host_to_country = {}

    for i in range(0, len(unique_hosts), 100):
        batch = unique_hosts[i:i+100]
        try:
            r = requests.post("http://ip-api.com/batch", json=batch, timeout=5)
            if r.status_code == 200:
                for row in r.json():
                    if row.get("status") == "success":
                        host_to_country[row.get("query")] = row.get("countryCode", "US")
        except Exception:
            pass

    for node in nodes:
        c_code = host_to_country.get(node.get("host"), "US")
        node["country"] = c_code
        # ‼️ این خطه که اون جادوی اسم رو میزنه:
        node["raw"] = rebrand_config(node.get("raw", ""), c_code)

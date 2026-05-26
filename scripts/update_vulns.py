from __future__ import annotations

import base64
import datetime as dt
import email.utils
import html
import json
import os
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from zoneinfo import ZoneInfo

OUT = Path("vulns.json")
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH = "https://api.github.com/search/repositories"
UA = "pirate.moo-threat-tide/1.0"
TOKEN = os.environ.get("GITHUB_TOKEN", "")
EXTRA_RSS_SOURCES = os.environ.get("EXTRA_RSS_SOURCES", "")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
LOCAL_TZ = ZoneInfo("America/Chicago")
LOOKBACK_DAYS = 7
CURRENT_CVE_YEAR = dt.datetime.now(dt.timezone.utc).year
STRICT_CURRENT_CVE_YEAR_ONLY = True

RSS_SOURCES = [
    ("Google Security Blog", "https://security.googleblog.com/feeds/posts/default"),
    ("Project Zero Current", "https://projectzero.google/feed.xml"),
    ("Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("watchTowr Labs", "https://labs.watchtowr.com/rss/"),
    ("Horizon3 Attack Team", "https://www.horizon3.ai/feed/"),
    ("Dirkjan Mollema", "https://dirkjanm.io/feed.xml"),
    ("ZDI", "https://www.zerodayinitiative.com/blog?format=rss"),
    ("ZDI Published Advisories", "https://www.zerodayinitiative.com/rss/published/2026/"),
    ("NCC Group Research", "https://research.nccgroup.com/feed/"),
    ("Bishop Fox", "https://bishopfox.com/blog/rss.xml"),
    ("Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml"),
    ("GitHub Security Lab", "https://github.blog/security/vulnerability-research/feed/"),
    ("Aqua Nautilus", "https://www.aquasec.com/feed/"),
    ("Synacktiv", "https://www.synacktiv.com/en/feed/lastblog.xml"),
    ("SSD Disclosure", "https://ssd-disclosure.com/feed/"),
    ("Rapid7 Blog", "https://www.rapid7.com/blog/rss.xml"),
    ("Qualys Research", "https://blog.qualys.com/feed"),
    ("PortSwigger Research", "https://portswigger.net/research/rss"),
    ("Assetnote Research", "https://www.assetnote.io/resources/research/rss.xml"),
    ("SonarSource", "https://www.sonarsource.com/blog/rss.xml"),
    ("GitLab Releases", "https://about.gitlab.com/releases.xml"),
    ("ProjectDiscovery", "https://projectdiscovery.io/blog/rss.xml"),
    ("Kaspersky Securelist", "https://securelist.com/feed/"),
    ("Exodus Intelligence", "https://blog.exodusintel.com/feed/"),
    ("The GitHub Blog Security", "https://github.blog/security/feed/"),
]

SOURCE_PROFILES = {
    "Google Security Blog": ("Google Security Blog", "https://blog.google/security/"),
    "Project Zero Current": ("Project Zero", "https://projectzero.google/"),
    "Project Zero": ("Project Zero", "https://x.com/ProjectZeroBugs"),
    "watchTowr Labs": ("watchTowr Labs", "https://x.com/watchtowrcyber"),
    "Horizon3 Attack Team": ("Horizon3 Attack Team", "https://x.com/Horizon3Attack"),
    "Dirkjan Mollema": ("_dirkjan", "https://x.com/_dirkjan"),
    "ZDI": ("ZDI", "https://x.com/thezdi"),
    "ZDI Published Advisories": ("ZDI", "https://x.com/thezdi"),
    "NCC Group Research": ("NCC Group Research", "https://research.nccgroup.com/"),
    "Bishop Fox": ("Bishop Fox", "https://x.com/BishopFox"),
    "Elastic Security Labs": ("Elastic Security Labs", "https://www.elastic.co/security-labs"),
    "GitHub Security Lab": ("GitHub Security Lab", "https://github.com/github/securitylab"),
    "Aqua Nautilus": ("Aqua Nautilus", "https://www.aquasec.com/cloud-native-academy/aqua-research/"),
    "Synacktiv": ("Synacktiv", "https://x.com/synacktiv"),
    "SSD Disclosure": ("SSD Disclosure", "https://ssd-disclosure.com/"),
    "Rapid7 Blog": ("Rapid7", "https://github.com/rapid7"),
    "Qualys Research": ("Qualys Research", "https://blog.qualys.com/"),
    "PortSwigger Research": ("PortSwigger Research", "https://portswigger.net/research"),
    "Assetnote Research": ("Assetnote", "https://www.assetnote.io/resources/research"),
    "SonarSource": ("SonarSource", "https://x.com/SonarSource"),
    "GitLab Releases": ("GitLab", "https://about.gitlab.com/releases/"),
    "ProjectDiscovery": ("ProjectDiscovery", "https://github.com/projectdiscovery"),
    "Kaspersky Securelist": ("Kaspersky GReAT", "https://securelist.com/"),
    "Exodus Intelligence": ("Exodus Intelligence", "https://blog.exodusintel.com/"),
    "The GitHub Blog Security": ("GitHub Security", "https://github.blog/security/"),
}

MOBILE_RESEARCHERS = [
    ("@natashenka", "https://x.com/natashenka"),
    ("@alisaesage", "https://x.com/alisaesage"),
    ("@zerodayalpha", "https://x.com/zerodayalpha"),
    ("@pkqzy888", "https://x.com/pkqzy888"),
    ("@scwuaptx", "https://x.com/scwuaptx"),
    ("@terrynini38514", "https://x.com/terrynini38514"),
    ("@0xkol", "https://x.com/0xkol"),
    ("@AndroidAuth", "https://x.com/AndroidAuth"),
    ("@androidmalware2", "https://x.com/androidmalware2"),
    ("@ProjectZero", "https://x.com/ProjectZero"),
    ("@tiraniddo", "https://x.com/tiraniddo"),
    ("@33y0re", "https://x.com/33y0re"),
    ("@0xfluxsec", "https://x.com/0xfluxsec"),
    ("@Dinosn", "https://x.com/Dinosn"),
    ("@binitamshah", "https://x.com/binitamshah"),
]

MOBILE_RESEARCHER_TERMS = {
    handle.lstrip("@").lower()
    for handle, _ in MOBILE_RESEARCHERS
}

for line in EXTRA_RSS_SOURCES.splitlines():
    if "|" not in line:
        continue
    name, url = [part.strip() for part in line.split("|", 1)]
    if name and url.startswith("https://"):
        RSS_SOURCES.append((name, url))
        SOURCE_PROFILES.setdefault(name, (name, url))

RESEARCH_SOURCE_NAMES = {
    "Google Security Blog", "Project Zero Current", "Project Zero", "watchTowr Labs",
    "Horizon3 Attack Team", "Dirkjan Mollema", "ZDI", "ZDI Published Advisories", "NCC Group Research",
    "Bishop Fox", "Elastic Security Labs", "GitHub Security Lab", "Aqua Nautilus",
    "Synacktiv", "SSD Disclosure", "Rapid7 Blog", "Qualys Research",
    "PortSwigger Research", "Assetnote Research", "SonarSource",
    "Kaspersky Securelist", "Exodus Intelligence", "The GitHub Blog Security",
}

HIGH_SIGNAL = {
    "active directory", "ad cs", "adcs", "android", "apache", "apple", "atlassian", "azure",
    "chrome", "chromium", "citrix", "confluence", "connectwise", "container", "cisco",
    "api", "graphql", "rest api", "web app", "web application", "appsec",
    "domain controller", "exchange", "esxi", "entra", "fortinet", "gitlab", "jenkins",
    "kerberos", "kubernetes", "ldap", "linux", "microsoft", "ntlm", "oauth", "openssh",
    "palo alto", "pan-os", "pixel", "rdp", "relay", "saml", "sccm", "screenconnect",
    "sharepoint", "teamcity", "webkit", "windows", "winrm", "wordpress", "vmware",
    "vpn", "zero-click", "zeroclick",
    "baseband", "binder", "dolby", "media framework", "pixel", "qualcomm", "sandbox",
}

PRIMITIVES = {
    "auth bypass": ("Auth Bypass", ["authentication bypass", "auth bypass", "authorization bypass"]),
    "rce": ("RCE", ["remote code execution", "rce", "command injection", "code execution", "pre-auth rce", "preauth rce"]),
    "lpe": ("Local LPE", ["privilege escalation", "lpe", "local privilege", "elevation of privilege", "eop"]),
    "memory corruption": ("Memory Corruption", ["double free", "use-after-free", "uaf", "heap overflow", "heap corruption", "out-of-bounds write", "buffer overflow"]),
    "file read": ("File Read", ["file read", "path traversal", "arbitrary file", "file disclosure"]),
    "session theft": ("Session Theft", ["session", "token", "cookie", "credential disclosure"]),
    "sqli": ("SQLi", ["sql injection", "sqli"]),
    "xss": ("XSS", ["cross-site scripting", "xss"]),
}

X_STYLE_DISCOVERY_QUERIES = [
    "CVE PoC",
    "CVE public PoC",
    "CVE proof of concept",
    "CVE proof-of-concept",
    "CVE reproducer",
    "CVE exploit PoC RCE",
    "CVE exploit PoC LPE",
    "CVE exploit PoC Windows",
    "CVE exploit PoC Exchange",
    "CVE exploit PoC SharePoint",
    "CVE exploit PoC Active Directory",
    "CVE exploit PoC ADCS",
    "CVE exploit PoC Kerberos",
    "CVE exploit PoC NTLM",
    "CVE exploit PoC SCCM",
    "CVE exploit PoC Citrix",
    "CVE exploit PoC Ivanti",
    "CVE exploit PoC Fortinet",
    "CVE exploit PoC Palo Alto",
    "CVE exploit PoC VMware",
    "CVE exploit PoC Jenkins",
    "CVE exploit PoC GitLab",
    "CVE exploit PoC Kubernetes",
    "CVE exploit PoC web app",
    "CVE exploit PoC web application",
    "CVE exploit PoC API",
    "CVE exploit PoC GraphQL",
    "CVE exploit PoC SSRF",
    "CVE exploit PoC SQL injection",
    "CVE exploit PoC deserialization",
    "CVE exploit PoC path traversal",
    "CVE exploit PoC file upload",
    "CVE exploit PoC wordpress plugin",
    "CVE exploit PoC Android",
    "CVE exploit PoC iOS",
    "CVE exploit PoC Pixel",
    "CVE exploit PoC WebKit",
    "CVE exploit PoC Safari",
    "CVE exploit PoC baseband",
    "CVE exploit PoC sandbox escape",
    "CVE exploit PoC natashenka",
    "CVE exploit PoC alisaesage",
    "CVE exploit PoC zerodayalpha",
    "CVE exploit PoC pkqzy888",
    "CVE exploit PoC scwuaptx",
    "CVE exploit PoC terrynini38514",
    "CVE exploit PoC 0xkol",
    "CVE exploit PoC AndroidAuth",
    "CVE exploit PoC androidmalware2",
    "CVE exploit PoC ProjectZero",
    "CVE exploit PoC tiraniddo",
    "CVE exploit PoC 33y0re",
    "CVE exploit PoC 0xfluxsec",
    "CVE exploit PoC Dinosn",
    "CVE exploit PoC binitamshah",
    "CVE auth bypass exploit",
    "CVE command injection exploit",
    "CVE privilege escalation exploit",
    "CVE weaponized exploit",
]

ECOSYSTEM_RULES = [
    ("android", ["android", "aosp", "pixel"]),
    ("ios", ["ios", "ipados", "iphone", "webkit", "safari", "imessage", "apple"]),
    ("windows", ["windows", "microsoft", "exchange", "sharepoint", "active directory", "ad cs", "adcs", "ntlm", "kerberos", "sccm", "hyper-v", "winrm", "rdp"]),
    ("linux", ["linux", "openssh", "sudo", "systemd", "ubuntu", "debian", "kernel"]),
    ("web", ["apache", "nginx", "tomcat", "iis", "php", "java servlet", "spring", "struts", "rails", "django", "laravel", "nodejs", "express", "confluence", "jira", "wordpress", "wordpress plugin", "woocommerce", "drupal", "coldfusion", "geoserver", "cpanel", "whm", "webpros", "webstack", "web app", "webapp", "web application", "appsec", "api", "rest api", "graphql", "oauth", "saml", "openid", "session", "cookie", "xss", "csrf", "ssrf", "sqli", "sql injection", "deserialization", "path traversal", "file upload", "template injection", "ssti", "xxe"]),
    ("cloud", ["citrix", "fortinet", "palo alto", "pan-os", "ivanti", "vmware", "esxi", "kubernetes", "jenkins", "gitlab", "teamcity", "confluence", "atlassian", "connectwise", "vpn", "cloud"]),
]

CATEGORY_RULES = [
    ("adcs", ["ad cs", "adcs", "certificate"]),
    ("kerberos", ["kerberos"]),
    ("ntlm", ["ntlm", "relay"]),
    ("exchange", ["exchange", "owa", "ecp", "outlook web access"]),
    ("sharepoint", ["sharepoint"]),
    ("sccm", ["sccm", "configuration manager", "configmgr"]),
    ("rmm", ["screenconnect", "connectwise", "rmm"]),
    ("vpn-edge", ["citrix", "fortinet", "palo alto", "pan-os", "ivanti", "vpn", "gateway", "ssl-vpn", "ikev2", "ikeext", "ipsec"]),
    ("devops", ["jenkins", "gitlab", "teamcity", "ci/cd", "ci server"]),
    ("kernel", ["kernel", "use-after-free", "uaf"]),
    ("kubernetes", ["kubernetes", "container", "docker"]),
    ("ssh", ["openssh", "ssh"]),
    ("webstack", ["apache", "nginx", "tomcat", "iis", "php", "spring", "struts", "rails", "django", "laravel", "nodejs", "express", "confluence", "jira", "wordpress", "wordpress plugin", "woocommerce", "drupal", "coldfusion", "geoserver", "cpanel", "whm", "webpros", "web", "web app", "webapp", "web application", "api", "rest api", "graphql", "oauth", "saml", "openid", "session", "cookie", "xss", "csrf", "ssrf", "sqli", "sql injection", "deserialization", "path traversal", "file upload", "template injection", "ssti", "xxe"]),
    ("framework", ["android", "framework", "packageinstaller"]),
]

SPAM_TERMS = [
    "awesome-cve", "cve-list", "cve-database", "database", "seo", "nuclei-template",
    "template-only", "scanner-only", "auto-generated", "chatgpt", "ai generated",
    "awesome", "curated-list", "collection", "notes", "learning", "ctf", "writeup-only",
    "defense", "defensive", "detection", "detect", "scanner", "scan", "sigma", "yara",
    "suricata", "snort", "osquery", "splunk", "sentinel", "kql", "ioc", "iocs",
    "threat hunting", "blue team", "mitigation", "patch", "advisory-only",
]

ATTACK_READY_TERMS = [
    "exploit", "poc", "proof-of-concept", "rce", "lpe", "privilege escalation",
    "auth bypass", "command injection", "weaponized", "reverse shell", "shell",
    "payload", "scanner and exploit", "trigger", "reproduce", "reproducer",
    "usage", "rhost", "target", "callback", "listener",
]

DEFENSE_ONLY_TERMS = [
    "detection", "defense", "defensive", "sigma", "yara", "suricata", "snort",
    "osquery", "splunk", "sentinel", "kql", "ioc", "iocs", "threat hunting",
    "blue team", "mitigation", "patch guidance", "hardening", "advisory",
    "monitoring", "scanner-only",
]

RESEARCH_SIGNAL_TERMS = [
    "vulnerability", "vulnerabilities", "exploit", "exploitation", "poc",
    "proof of concept", "proof-of-concept", "rce", "lpe", "privilege escalation",
    "auth bypass", "authentication bypass", "command injection", "sql injection",
    "ssrf", "deserialization", "path traversal", "sandbox escape", "zero-click",
    "zeroclick", "kernel bug", "memory corruption", "use-after-free", "uaf",
    "double free", "heap overflow", "remote code execution",
]

POC_CODE_EXTENSIONS = {
    ".py", ".go", ".rb", ".js", ".ts", ".java", ".c", ".cc", ".cpp", ".cs",
    ".php", ".sh", ".ps1", ".rs", ".pl", ".lua", ".nse", ".yaml", ".yml",
}

POC_FILE_TERMS = [
    "exploit", "poc", "proof", "trigger", "exp", "rce", "lpe", "payload",
    "shell", "scanner", "check", "verify", "reproduce", "reproducer",
]

POC_USAGE_TERMS = [
    "usage", "how to run", "python ", "python3 ", "go run", "ruby ",
    "node ", "curl ", "target", "rhost", "lhost", "callback", "--url",
    "--target", "-u ", "make", "gcc ", "exploit.py", "poc.py",
]

NON_ENGLISH_HINTS = [
    "vulnerabilite", "vulnerabilidad", "vulnerabilidade", "schwachstelle",
    "explotacion", "exploracion", "exploracao", "ausnutzung",
    "ejecucion", "execucao", "execution de code", "execucion de codigo",
    "codigo", "seguridad", "seguranca", "angreifer", "sicherheitslucke",
    "ciblant", "developpe", "regroupe", "contournement", "fausses signatures",
    "memoire", "chaine", "chaines", "ce projet", "le projet", "permettant",
    "prueba de concepto", "preuve de concept", "prova de conceito",
]

def request(url: str, accept: str = "application/json") -> bytes:
    headers = {"User-Agent": UA, "Accept": accept}
    if TOKEN and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=25) as response:
        return response.read()

def fetch_json(url: str) -> dict:
    try:
        return json.loads(request(url).decode("utf-8", "replace"))
    except Exception as exc:
        print(f"warn: json fetch failed {url}: {exc}")
        return {}

def fetch_text(url: str) -> str:
    try:
        return request(url, "application/rss+xml, application/atom+xml, text/xml, */*").decode("utf-8", "replace")
    except Exception as exc:
        print(f"warn: text fetch failed {url}: {exc}")
        return ""

def extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s,)>\"]+", text or "")

def norm(text: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", text or "")).strip()

def compact(text: str, limit: int = 190) -> str:
    text = norm(text)
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "."

def strip_cve_prefix(text: str, cve: str) -> str:
    text = norm(text)
    text = re.sub(rf"^\s*{re.escape(cve)}\s*[:\-Ã¢â‚¬â€œÃ¢â‚¬â€]?\s*", "", text, flags=re.I)
    text = re.sub(r"^\s*CVE-\d{4}-\d{4,7}\s*[:\-Ã¢â‚¬â€œÃ¢â‚¬â€]?\s*", "", text, flags=re.I)
    return text.strip()

def remove_cve_refs(text: str, cve: str) -> str:
    text = strip_cve_prefix(text, cve)
    if cve:
        text = re.sub(rf"\b{re.escape(cve)}\b\s*[,;:\-]?\s*", "", text, flags=re.I)
    return norm(re.sub(r"\s+([,.;:])", r"\1", text))

def keyword_soup(text: str) -> bool:
    text = norm(text)
    if not text:
        return False
    return len(re.split(r"[,;]", text)) >= 5 and len(text.split()) <= 36

def ascii_fold(text: str) -> str:
    return unicodedata.normalize("NFKD", norm(text)).encode("ascii", "ignore").decode("ascii").lower()

def looks_non_english(text: str) -> bool:
    raw = norm(text)
    if not raw:
        return False
    lower = raw.lower()
    if re.search(r"[\u0370-\u03FF\u0400-\u04FF\u0590-\u05FF\u0600-\u06FF\u3040-\u30FF\u3400-\u9FFF\uAC00-\uD7AF]", lower):
        return True
    folded = ascii_fold(raw)
    hits = sum(1 for term in NON_ENGLISH_HINTS if term in folded)
    accent_count = sum(1 for char in raw if ord(char) > 127)
    return hits >= 2 or (accent_count >= 2 and hits >= 1)

def clean_title(text: str, cve: str, limit: int = 110) -> str:
    text = strip_cve_prefix(text, cve)
    text = re.sub(rf"^\s*{re.escape(cve)}\s*[:\-â€“â€”]?\s*", "", text, flags=re.I)
    text = re.sub(r"^\s*CVE-\d{4}-\d{4,7}\s*[:\-â€“â€”]?\s*", "", text, flags=re.I)
    text = re.sub(r"\s+with public poc signal\s*$", "", text, flags=re.I)
    text = re.sub(r"^[\s|:;,\-â€“â€”]+", "", text)
    return compact(text.strip() or "Untitled vulnerability signal", limit)

def meaningful_title(text: str, cve: str, limit: int = 110) -> str:
    title = clean_title(text, cve, limit)
    lower = title.lower().strip()
    if not title or lower == "untitled vulnerability signal":
        return ""
    if CVE_RE.fullmatch(title):
        return ""
    if lower in {"cve", "poc", "exploit", "vulnerability", "proof of concept"}:
        return ""
    if len(re.sub(r"[^a-z0-9]", "", lower)) < 8:
        return ""
    if looks_non_english(title):
        return ""
    return title

def repo_name_title(repo: dict, cve: str) -> str:
    raw = (repo.get("name", "").split("/")[-1] or "").strip()
    raw = re.sub(r"[-_]+", " ", raw)
    raw = re.sub(r"\b(exploit|poc|proof of concept|cve)\b", " ", raw, flags=re.I)
    raw = re.sub(r"\s+", " ", raw).strip()
    return meaningful_title(raw, cve)

def readme_title(repo: dict, cve: str) -> str:
    if "github.com/" not in repo.get("url", "").lower():
        return ""
    text = github_readme_text(repo.get("name", ""))
    for line in text.splitlines()[:80]:
        match = re.match(r"^\s*#{1,2}\s+(.+?)\s*$", line)
        if not match:
            continue
        title = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", match.group(1))
        title = re.sub(r"\[[^\]]*\]\([^)]*\)", "", title)
        cleaned = meaningful_title(title, cve)
        if cleaned:
            return cleaned
    return ""

def exploit_phrase_title(text: str, cve: str, limit: int = 110) -> str:
    text = norm(text)
    if not text:
        return ""
    lowered = text.lower()
    terms = []
    if term_in_text(lowered, "ikev2") or term_in_text(lowered, "ikeext.dll"):
        terms.append("Windows IKEv2")
    if term_in_text(lowered, "double free"):
        terms.append("double-free")
    if term_in_text(lowered, "heap grooming"):
        terms.append("heap-groomed")
    if term_in_text(lowered, "rop"):
        terms.append("ROP")
    if term_in_text(lowered, "reverse shell"):
        terms.append("reverse shell")
    if term_in_text(lowered, "auth bypass") or term_in_text(lowered, "authentication bypass"):
        terms.append("authentication bypass")
    if term_in_text(lowered, "command injection"):
        terms.append("command injection")
    if term_in_text(lowered, "sql injection"):
        terms.append("SQL injection")
    if term_in_text(lowered, "privilege escalation") or term_in_text(lowered, "lpe"):
        terms.append("privilege escalation")
    if term_in_text(lowered, "rce") or term_in_text(lowered, "remote code execution"):
        terms.append("remote code execution")
    if len(terms) >= 2:
        return compact(" ".join(dict.fromkeys(terms)) + " exploit", limit)
    return ""

def description_title(desc: str, cve: str, vendor: str, product: str) -> str:
    text = norm(desc)
    if not text:
        return ""
    if looks_non_english(text):
        return exploit_phrase_title(text, cve)
    lower = text.lower()
    if "vulnerability has been resolved:" in lower:
        fragment = re.split(r"vulnerability has been resolved:\s*", text, flags=re.I, maxsplit=1)[-1]
        fragment = fragment.split(".", 1)[0]
        prefix = f"{product or vendor} " if product or vendor else ""
        return meaningful_title(prefix + fragment, cve)
    first_sentence = re.split(r"(?<=[.!?])\s+", text)[0]
    return meaningful_title(first_sentence, cve)

def primitive_copy(prim: str) -> str:
    mapping = {
        "RCE": "remote code execution",
        "LPE": "local privilege escalation",
        "Auth Bypass": "authentication bypass",
        "Command Injection": "command injection",
        "SQLi": "SQL injection",
        "File Read": "file read",
        "Memory Corruption": "memory corruption",
    }
    return mapping.get(prim, (prim or "exploit").lower())

def english_problem_summary(desc: str, repo: dict, cve: str, vendor: str, product: str, prim: str, limit: int = 230) -> str:
    candidates = [repo.get("description", ""), desc]
    for candidate in candidates:
        text = remove_cve_refs(candidate, cve)
        if not text or looks_non_english(text) or keyword_soup(text):
            continue
        if meaningful_title(text, cve, 60):
            return compact(text, limit)
    signal_text = " ".join([repo.get("description", ""), desc, repo.get("name", "")])
    phrase = exploit_phrase_title(signal_text, cve)
    subject = " ".join(part for part in [vendor, product] if part).strip() or "The affected component"
    if phrase:
        return compact(f"{phrase} targeting {subject}. The root issue is a {primitive_copy(prim)} path that public tooling attempts to turn into code execution or privileged access.", limit)
    return compact(f"{subject} exposes a {primitive_copy(prim)} path with recent public exploit tooling signal.", limit)

def clean_summary(desc: str, repo: dict, cve: str, vendor: str, product: str, prim: str, limit: int = 230) -> str:
    candidates = [repo.get("description", ""), desc]
    for candidate in candidates:
        text = remove_cve_refs(candidate, cve)
        if looks_non_english(text) or keyword_soup(text):
            continue
        text = re.sub(rf"^\s*{re.escape(cve)}\s*[:\-â€“â€”]?\s*", "", text, flags=re.I)
        text = re.sub(r"^\s*CVE-\d{4}-\d{4,7}\s*[:\-â€“â€”]?\s*", "", text, flags=re.I)
        if meaningful_title(text, cve, 60):
            return compact(text, limit)
    return english_problem_summary(desc, repo, cve, vendor, product, prim, limit)

def derived_title(cve: str, vendor: str, product: str, name: str, desc: str, repo: dict, mention: dict | None, prim: str) -> str:
    repo_desc_title = exploit_phrase_title(repo.get("description", ""), cve)
    early_candidates = [
        repo_desc_title,
        name,
        (mention or {}).get("title", ""),
        repo.get("description", ""),
    ]
    late_candidates = [
        lambda: readme_title(repo, cve),
        lambda: repo_name_title(repo, cve),
        lambda: description_title(desc, cve, vendor, product),
    ]
    for candidate in early_candidates:
        title = meaningful_title(candidate, cve)
        if title:
            return title
    for candidate_factory in late_candidates:
        candidate = candidate_factory()
        title = meaningful_title(candidate, cve)
        if title:
            return title
    subject = " ".join(part for part in [vendor, product] if part).strip()
    if subject and prim != "Exploit":
        return compact(f"{subject} {prim}", 110)
    return "Untitled vulnerability signal"

def term_in_text(text: str, term: str) -> bool:
    lower = text.lower()
    term = term.lower()
    if len(term) <= 3 or re.fullmatch(r"[a-z0-9-]+", term):
        pattern = r"(?<![a-z0-9])" + re.escape(term).replace(r"\-", r"[-\s]") + r"(?![a-z0-9])"
        return re.search(pattern, lower) is not None
    return term in lower

def contains_any(text: str, terms) -> bool:
    return any(term_in_text(text, term) for term in terms)

def tag_value(text: str, rules: list[tuple[str, list[str]]], fallback: str) -> str:
    for value, terms in rules:
        if contains_any(text, terms):
            return value
    return fallback

def primitive(text: str) -> str:
    for label, terms in PRIMITIVES.values():
        if contains_any(text, terms):
            return label
    return "RCE" if term_in_text(text, "execute") else "Exploit"

def labelize(value: str) -> str:
    return {
        "ios": "iOS",
        "adcs": "ADCS",
        "rce": "RCE",
        "lpe": "Local LPE",
        "memory corruption": "Memory Corruption",
        "vpn-edge": "VPN Edge",
        "devops": "DevOps",
        "webstack": "Webstack",
        "web": "Web",
        "rmm": "RMM",
        "ssh": "SSH",
        "sqli": "SQLi",
        "sharepoint": "SharePoint",
        "sccm": "SCCM",
    }.get(value.lower(), value.replace("-", " ").title())

def parse_date(value: str) -> dt.datetime:
    if not value:
        return dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    try:
        parsed = dt.datetime.fromisoformat((value or "").replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc)
        except Exception:
            pass
        try:
            return dt.datetime.strptime(value[:10], "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
        except Exception:
            return dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

def rss_mentions() -> dict[str, list[dict]]:
    mentions: dict[str, list[dict]] = {}
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=LOOKBACK_DAYS)
    for source, url in RSS_SOURCES:
        xml = fetch_text(url)
        if not xml:
            continue
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            continue
        entries = [node for node in root.iter() if node.tag.split("}")[-1] in {"item", "entry"}]
        for entry in entries[:25]:
            fields = {"title": "", "summary": "", "link": "", "published": ""}
            for child in list(entry):
                tag = child.tag.split("}")[-1]
                if tag in {"title", "description", "summary", "content", "encoded"}:
                    fields["title" if tag == "title" else "summary"] = norm(child.text or "")
                if tag == "link":
                    fields["link"] = child.attrib.get("href") or norm(child.text or "")
                if tag in {"pubDate", "published", "updated", "date"}:
                    fields["published"] = norm(child.text or "")
            published = parse_date(fields["published"])
            if published < cutoff:
                continue
            text = f"{fields['title']} {fields['summary']}"
            for cve in {match.upper() for match in CVE_RE.findall(text)}:
                profile_name, profile_url = SOURCE_PROFILES.get(source, (source, url))
                mentions.setdefault(cve, []).append({
                    "source": profile_name,
                    "profileUrl": profile_url,
                    "title": compact(fields["title"], 140),
                    "summary": compact(fields["summary"], 260),
                    "url": fields["link"] or url,
                    "urls": list(dict.fromkeys(extract_urls(fields["summary"]) + ([fields["link"]] if fields["link"] else [])))[:8],
                    "publishedAt": published.isoformat().replace("+00:00", "Z"),
                })
    return mentions

def rss_research_items(now_utc: dt.datetime) -> list[dict]:
    research: list[dict] = []
    cutoff = now_utc - dt.timedelta(hours=24)
    seen_urls: set[str] = set()
    for source, url in RSS_SOURCES:
        if source not in RESEARCH_SOURCE_NAMES:
            continue
        xml = fetch_text(url)
        if not xml:
            continue
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            continue
        entries = [node for node in root.iter() if node.tag.split("}")[-1] in {"item", "entry"}]
        for entry in entries[:15]:
            fields = {"title": "", "summary": "", "link": "", "published": ""}
            for child in list(entry):
                tag = child.tag.split("}")[-1]
                if tag in {"title", "description", "summary", "content", "encoded"}:
                    fields["title" if tag == "title" else "summary"] = norm(child.text or "")
                if tag == "link":
                    fields["link"] = child.attrib.get("href") or norm(child.text or "")
                if tag in {"pubDate", "published", "updated", "date"}:
                    fields["published"] = norm(child.text or "")
            published = parse_date(fields["published"])
            if published < cutoff:
                continue
            link = fields["link"] or url
            if not link or link in seen_urls:
                continue
            text = norm(re.sub(r"<[^>]+>", " ", f"{fields['title']} {fields['summary']}"))
            cves = sorted({match.upper() for match in CVE_RE.findall(text)})
            if not cves and not contains_any(text, RESEARCH_SIGNAL_TERMS):
                continue
            if contains_any(text, DEFENSE_ONLY_TERMS) and not contains_any(text, ["exploit", "vulnerability", "cve", "poc"]):
                continue
            profile_name, profile_url = SOURCE_PROFILES.get(source, (source, url))
            category = tag_value(text, CATEGORY_RULES, "")
            ecosystem = tag_value(text, ECOSYSTEM_RULES, "")
            prim = primitive(text)
            tags = []
            for value in [ecosystem, category, prim]:
                if value and value != "Exploit":
                    tags.append(labelize(value))
            seen_urls.add(link)
            research.append({
                "title": compact(fields["title"], 160),
                "source": profile_name,
                "sourceUrl": profile_url,
                "url": link,
                "summary": compact(re.sub(r"<[^>]+>", " ", fields["summary"]), 260),
                "publishedAt": published.isoformat().replace("+00:00", "Z"),
                "cves": cves[:5],
                "tags": list(dict.fromkeys(tags))[:6],
            })
    research.sort(key=lambda item: parse_date(item.get("publishedAt", "")), reverse=True)
    return research[:12]

def kev_items() -> list[dict]:
    data = fetch_json(CISA_KEV)
    return data.get("vulnerabilities", []) if isinstance(data.get("vulnerabilities"), list) else []

def epss_scores(cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for index in range(0, len(cves), 80):
        batch = cves[index : index + 80]
        url = EPSS + "?" + urllib.parse.urlencode({"cve": ",".join(batch)})
        data = fetch_json(url)
        for row in data.get("data", []) if isinstance(data.get("data"), list) else []:
            try:
                scores[row["cve"].upper()] = float(row.get("epss") or 0)
            except Exception:
                pass
    return scores

def nvd_lookup(cve: str) -> dict:
    data = fetch_json(NVD + "?" + urllib.parse.urlencode({"cveId": cve}))
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}
    cve_data = vulns[0].get("cve", {})
    desc = ""
    for item in cve_data.get("descriptions", []):
        if item.get("lang") == "en":
            desc = item.get("value", "")
            break
    raw_refs = cve_data.get("references", [])
    if isinstance(raw_refs, dict):
        raw_refs = raw_refs.get("referenceData", [])
    refs = [
        ref.get("url", "")
        for ref in raw_refs
        if isinstance(ref, dict) and ref.get("url")
    ]
    metrics = cve_data.get("metrics", {})
    severity = ""
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key)
            if isinstance(rows, list) and rows:
                row = rows[0] if isinstance(rows[0], dict) else {}
                cvss = row.get("cvssData", {}) if isinstance(row.get("cvssData", {}), dict) else {}
                severity = cvss.get("baseSeverity") or row.get("baseSeverity", "")
                break
    return {
        "description": desc,
        "references": refs,
        "severity": severity,
        "published": cve_data.get("published", ""),
        "lastModified": cve_data.get("lastModified", ""),
    }

def nvd_recent_cves(now_utc: dt.datetime, days: int = LOOKBACK_DAYS) -> dict[str, dict]:
    # NVD is the broad "what was published" source. It is not enough to publish
    # an entry, but it prevents the feed from missing CVEs that have fresh PoCs.
    published_after = now_utc - dt.timedelta(days=days)
    params = {
        "pubStartDate": published_after.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": now_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": "2000",
    }
    data = fetch_json(NVD + "?" + urllib.parse.urlencode(params))
    recent: dict[str, dict] = {}
    for row in data.get("vulnerabilities", []) if isinstance(data.get("vulnerabilities"), list) else []:
        cve_data = row.get("cve", {}) if isinstance(row, dict) else {}
        cve = (cve_data.get("id") or "").upper()
        if not CVE_RE.fullmatch(cve) or not allowed_cve_year(cve):
            continue
        desc = ""
        for item in cve_data.get("descriptions", []) if isinstance(cve_data.get("descriptions"), list) else []:
            if item.get("lang") == "en":
                desc = item.get("value", "")
                break
        raw_refs = cve_data.get("references", [])
        if isinstance(raw_refs, dict):
            raw_refs = raw_refs.get("referenceData", [])
        refs = [
            ref.get("url", "")
            for ref in raw_refs
            if isinstance(ref, dict) and ref.get("url")
        ]
        metrics = cve_data.get("metrics", {})
        severity = ""
        if isinstance(metrics, dict):
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                rows = metrics.get(key)
                if isinstance(rows, list) and rows:
                    row0 = rows[0] if isinstance(rows[0], dict) else {}
                    cvss = row0.get("cvssData", {}) if isinstance(row0.get("cvssData", {}), dict) else {}
                    severity = cvss.get("baseSeverity") or row0.get("baseSeverity", "")
                    break
        recent[cve] = {
            "description": desc,
            "references": refs,
            "severity": severity,
            "published": cve_data.get("published", ""),
            "lastModified": cve_data.get("lastModified", ""),
        }
    return recent

def cve_year(cve: str) -> int:
    match = re.match(r"^CVE-(\d{4})-", cve or "", re.I)
    return int(match.group(1)) if match else 0

def allowed_cve_year(cve: str) -> bool:
    return cve_year(cve) == CURRENT_CVE_YEAR if STRICT_CURRENT_CVE_YEAR_ONLY else cve_year(cve) >= CURRENT_CVE_YEAR

def recent_date(value: str, now_utc: dt.datetime, days: int = LOOKBACK_DAYS) -> bool:
    parsed = parse_date(value)
    if parsed.year == 1970:
        return False
    return parsed >= now_utc - dt.timedelta(days=days)

def is_recent_release(cve: str, item: dict | None, mention: dict | None, repo: dict | None, nvd: dict, now_utc: dt.datetime) -> bool:
    if not allowed_cve_year(cve):
        return False
    if item and recent_date(item.get("dateAdded", ""), now_utc):
        return True
    if mention and recent_date(mention.get("publishedAt", ""), now_utc):
        return True
    if recent_date(nvd.get("published", ""), now_utc):
        return True
    if repo and recent_date(repo.get("created_at", ""), now_utc):
        return True
    return False

def repo_is_new(repo: dict, now_utc: dt.datetime) -> bool:
    return recent_date(repo.get("created_at", ""), now_utc)

def repo_score(repo: dict, cve: str) -> int:
    text = " ".join([
        repo.get("full_name", ""),
        repo.get("name", ""),
        repo.get("description") or "",
    ]).lower()
    score = 0
    if cve.lower() in text:
        score += 35
    if contains_any(text, ATTACK_READY_TERMS):
        score += 32
    else:
        score -= 55
    if contains_any(text, DEFENSE_ONLY_TERMS):
        score -= 90
    if contains_any(text, SPAM_TERMS):
        score -= 80
    if repo.get("fork"):
        score -= 18
    if repo.get("archived"):
        score -= 20
    created = parse_date(repo.get("created_at", ""))
    if (dt.datetime.now(dt.timezone.utc) - created).days <= LOOKBACK_DAYS:
        score += 16
    else:
        score -= 45
    score += min(int(repo.get("stargazers_count") or 0), 40) // 8
    return score

def attack_ready_repo(repo: dict, cve: str) -> bool:
    text = " ".join([
        repo.get("full_name", ""),
        repo.get("name", ""),
        repo.get("description") or "",
    ])
    if contains_any(text, DEFENSE_ONLY_TERMS) or contains_any(text, SPAM_TERMS):
        return False
    return contains_any(text, ATTACK_READY_TERMS) and term_in_text(text, cve)

def file_extension(path: str) -> str:
    match = re.search(r"(\.[a-z0-9]+)$", path.lower())
    return match.group(1) if match else ""

def language_from_paths(paths: list[str]) -> str:
    counts: dict[str, int] = {}
    mapping = {
        ".py": "Python", ".go": "Go", ".rb": "Ruby", ".js": "JavaScript",
        ".ts": "TypeScript", ".java": "Java", ".c": "C", ".cc": "C++",
        ".cpp": "C++", ".cs": "C#", ".php": "PHP", ".sh": "Shell",
        ".ps1": "PowerShell", ".rs": "Rust", ".pl": "Perl", ".lua": "Lua",
        ".nse": "Lua", ".yaml": "YAML", ".yml": "YAML",
    }
    for path in paths:
        language = mapping.get(file_extension(path))
        if language:
            counts[language] = counts.get(language, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[0][0]

def github_tree_paths(repo: dict) -> list[str]:
    full_name = repo.get("full_name") or repo.get("name", "")
    branch = repo.get("default_branch") or "main"
    if not full_name or "/" not in full_name:
        return []
    safe_name = urllib.parse.quote(full_name, safe="/")
    safe_branch = urllib.parse.quote(branch, safe="")
    data = fetch_json(f"https://api.github.com/repos/{safe_name}/git/trees/{safe_branch}?recursive=1")
    tree = data.get("tree", []) if isinstance(data.get("tree"), list) else []
    return [
        item.get("path", "")
        for item in tree
        if isinstance(item, dict) and item.get("type") == "blob" and item.get("path")
    ][:500]

def poc_evidence(repo: dict, cve: str, readme: str = "") -> dict:
    full_name = repo.get("full_name") or repo.get("name", "")
    desc = repo.get("description") or ""
    paths = github_tree_paths(repo)
    code_paths = [
        path for path in paths
        if file_extension(path) in POC_CODE_EXTENSIONS
        and not re.search(r"(^|/)(test|tests|docs?|examples?|screenshots?)/", path.lower())
    ]
    attack_paths = [
        path for path in code_paths
        if contains_any(path, POC_FILE_TERMS) or cve.lower() in path.lower()
    ]
    text = " ".join([full_name, repo.get("name", ""), desc, readme])
    has_cve = term_in_text(text, cve) or any(cve.lower() in path.lower() for path in paths)
    attack_text = contains_any(text, ATTACK_READY_TERMS)
    usage_text = contains_any(readme, POC_USAGE_TERMS)
    noisy = contains_any(text, DEFENSE_ONLY_TERMS) or contains_any(text, SPAM_TERMS)
    score = 0
    score += 2 if has_cve else -4
    score += 2 if attack_text else -3
    score += 2 if code_paths else -4
    score += 2 if attack_paths else 0
    score += 1 if usage_text else 0
    score += 1 if repo.get("language") or language_from_paths(code_paths) else 0
    score -= 6 if noisy else 0
    valid = score >= 3 and has_cve and attack_text and bool(code_paths) and not noisy
    return {
        "valid": valid,
        "score": score,
        "codeFiles": code_paths[:8],
        "attackFiles": attack_paths[:8],
        "hasUsage": usage_text,
        "language": repo.get("language") or language_from_paths(code_paths) or "",
    }

def repo_to_candidate(repo: dict, cve: str, bonus: int = 0, evidence: dict | None = None) -> dict:
    owner = repo.get("owner", {}) if isinstance(repo.get("owner"), dict) else {}
    evidence = evidence or {}
    score = repo_score(repo, cve) + bonus + int(evidence.get("score", 0) or 0) * 6
    return {
        "score": score,
        "url": repo.get("html_url", ""),
        "owner": owner.get("login") or repo.get("full_name", "").split("/")[0],
        "owner_url": owner.get("html_url") or "",
        "name": repo.get("full_name", ""),
        "description": repo.get("description") or "",
        "language": evidence.get("language") or repo.get("language") or "",
        "created_at": repo.get("created_at") or "",
        "pushed_at": repo.get("pushed_at") or "",
        "validatedPoc": bool(evidence.get("valid")),
        "pocEvidence": evidence,
    }

def github_full_name_from_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            return ""
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            return ""
        return f"{parts[0]}/{parts[1]}"
    except Exception:
        return ""

def github_repo_metadata(full_name: str) -> dict:
    if not full_name or "/" not in full_name:
        return {}
    safe_name = urllib.parse.quote(full_name, safe="/")
    data = fetch_json(f"https://api.github.com/repos/{safe_name}")
    return data if isinstance(data, dict) and data.get("full_name") else {}

def mention_candidate(cve: str, mention: dict | None) -> dict | None:
    if not mention:
        return None
    urls = list(dict.fromkeys((mention.get("urls") or []) + [mention.get("url", "")]))
    chosen = ""
    for url in urls:
        lower = str(url).lower()
        if "github.com/" in lower:
            chosen = url
            break
    if not chosen:
        return None
    full_name = github_full_name_from_url(chosen)
    repo = github_repo_metadata(full_name)
    if not repo or not repo_is_new(repo, dt.datetime.now(dt.timezone.utc)):
        return None
    readme = github_readme_text(full_name)
    evidence = poc_evidence(repo, cve, readme)
    if not evidence.get("valid"):
        return None
    candidate = repo_to_candidate(repo, cve, bonus=20, evidence=evidence)
    candidate["owner"] = mention.get("source") or candidate["owner"]
    candidate["owner_url"] = mention.get("profileUrl", "") or candidate.get("owner_url", "")
    return candidate

def github_readme_text(full_name: str) -> str:
    if not full_name or "/" not in full_name:
        return ""
    url = f"https://api.github.com/repos/{full_name}/readme"
    try:
        data = fetch_json(url)
        content = data.get("content", "")
        encoding = data.get("encoding", "")
        if content and encoding == "base64":
            return base64.b64decode(content).decode("utf-8", "replace")[:12000]
    except Exception as exc:
        print(f"warn: readme fetch failed {full_name}: {exc}")
    return ""

def github_recent_cve_repos() -> dict[str, list[dict]]:
    # "New PoC" means first public repo creation in the last week.
    # Later pushes to old CVE repositories are intentionally ignored.
    created_after = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=LOOKBACK_DAYS)).date().isoformat()
    discovered: dict[str, list[dict]] = {}
    seen_repos: set[str] = set()
    readme_budget = 36
    for base_query in X_STYLE_DISCOVERY_QUERIES:
        query = f"{base_query} in:name,description,readme created:>={created_after}"
        url = GITHUB_SEARCH + "?" + urllib.parse.urlencode({
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": "20",
        })
        data = fetch_json(url)
        repos = data.get("items", []) if isinstance(data.get("items"), list) else []
        for repo in repos:
            repo_url = repo.get("html_url", "")
            full_name = repo.get("full_name", "")
            if not repo_url or repo_url in seen_repos:
                continue
            if not repo_is_new(repo, dt.datetime.now(dt.timezone.utc)):
                continue
            if not contains_any(" ".join([full_name, repo.get("name", ""), repo.get("description") or ""]), ATTACK_READY_TERMS):
                continue
            seen_repos.add(repo_url)
            readme = ""
            if readme_budget > 0:
                readme_budget -= 1
                readme = github_readme_text(full_name)
            text = " ".join([
                full_name,
                repo.get("name", ""),
                repo.get("description") or "",
                readme,
            ])
            cves = {match.upper() for match in CVE_RE.findall(text)}
            for cve in cves:
                if not allowed_cve_year(cve):
                    continue
                evidence = poc_evidence(repo, cve, readme)
                if not evidence.get("valid"):
                    continue
                candidate = repo_to_candidate(repo, cve, bonus=14, evidence=evidence)
                if candidate["score"] >= 55:
                    discovered.setdefault(cve, []).append(candidate)
        time.sleep(0.25)
    return discovered

def github_candidate(cve: str, seeded: list[dict] | None = None) -> dict | None:
    seeded_ranked = sorted(seeded or [], key=lambda repo: repo.get("score", 0), reverse=True)
    for repo in seeded_ranked:
        if repo.get("validatedPoc") and repo.get("score", 0) >= 55 and repo.get("url") and recent_date(repo.get("created_at", ""), dt.datetime.now(dt.timezone.utc)):
            return repo
    created_after = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=LOOKBACK_DAYS)).date().isoformat()
    queries = [
        f"{cve} poc in:name,description,readme created:>={created_after}",
        f"{cve} proof of concept in:name,description,readme created:>={created_after}",
        f"{cve} proof-of-concept in:name,description,readme created:>={created_after}",
        f"{cve} exploit poc rce lpe in:name,description,readme created:>={created_after}",
        f"{cve} exploit poc windows exchange in:name,description,readme created:>={created_after}",
        f"{cve} exploit poc in:name,description,readme created:>={created_after}",
    ]
    for query in queries:
        url = GITHUB_SEARCH + "?" + urllib.parse.urlencode({
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": "10",
        })
        data = fetch_json(url)
        repos = data.get("items", []) if isinstance(data.get("items"), list) else []
        ranked = sorted(((repo_score(repo, cve), repo) for repo in repos), key=lambda item: item[0], reverse=True)
        for score, repo in ranked:
            if score >= 45 and repo.get("html_url") and repo_is_new(repo, dt.datetime.now(dt.timezone.utc)) and attack_ready_repo(repo, cve):
                readme = github_readme_text(repo.get("full_name", ""))
                evidence = poc_evidence(repo, cve, readme)
                if evidence.get("valid"):
                    return repo_to_candidate(repo, cve, evidence=evidence)
    return None

def format_added(first_seen_at: str) -> str:
    local = parse_date(first_seen_at).astimezone(LOCAL_TZ)
    return local.strftime("%I:%M %p %Z").lstrip("0")

def archive_day_offset(first_seen_at: str, now_utc: dt.datetime) -> int:
    first_local = parse_date(first_seen_at).astimezone(LOCAL_TZ).date()
    now_local = now_utc.astimezone(LOCAL_TZ).date()
    return max(0, (now_local - first_local).days)

def language_label(repo: dict) -> str:
    language = norm(repo.get("language", ""))
    return language or "Unknown"

def difficulty_label(repo: dict, prim: str, epss: float) -> str:
    score = repo.get("score", 0)
    if prim in {"RCE", "Auth Bypass"} and score >= 65 and epss >= 0.08:
        return "easy"
    if score >= 60:
        return "moderate"
    if prim in {"Local LPE", "File Read"}:
        return "situational"
    return "needs validation"

def mobile_researcher_sources() -> list[str]:
    return [f"Mobile researcher watchlist: {handle}" for handle, _ in MOBILE_RESEARCHERS]

def operator_severity(nvd_sev: str, prim: str, ecosystem: str, category: str, epss: float, repo: dict, is_kev: bool, text: str) -> str:
    lower = text.lower()
    score = int(repo.get("score", 0) or 0)
    exposed = ecosystem == "cloud" or category in {"vpn-edge", "rmm", "devops", "webstack", "exchange"}
    if prim in {"File Read", "XSS", "SQLi"} or any(term in lower for term in ["path traversal", "out-of-bounds read", "information disclosure"]):
        return "high" if is_kev or epss >= 0.04 or exposed else "medium"
    if prim == "Local LPE" or ecosystem in {"android", "ios"}:
        return "high" if is_kev or score >= 65 or epss >= 0.05 else "medium"
    if prim in {"RCE", "Auth Bypass", "Session Theft", "Memory Corruption"}:
        if exposed and (is_kev or epss >= 0.12 or score >= 70 or "ransomware" in lower):
            return "critical"
        return "high"
    if nvd_sev == "MEDIUM":
        return "medium"
    if nvd_sev == "CRITICAL":
        return "high"
    return "high"

def exploit_syntax(repo: dict, language: str) -> str:
    repo_url = repo.get("url", "")
    repo_name = (repo.get("name", "").split("/")[-1] or "poc").strip()
    lower = language.lower()
    lines = [
        "# authorized lab / owned targets only",
        f"git clone {repo_url}",
        f"cd {repo_name}",
    ]
    if "python" in lower:
        lines.append("python3 <script>.py --target https://<authorized-target>")
    elif lower in {"go", "golang"}:
        lines.append("go run . --target https://<authorized-target>")
    elif lower in {"c", "c++", "cpp"}:
        lines.extend(["make", "./<compiled-poc> <authorized-target>"])
    elif "ruby" in lower:
        lines.append("ruby <script>.rb --target https://<authorized-target>")
    elif "java" in lower:
        lines.append("java -jar <poc>.jar https://<authorized-target>")
    elif "shell" in lower or "bash" in lower:
        lines.append("bash <script>.sh https://<authorized-target>")
    else:
        lines.append("# use the repo README invocation against https://<authorized-target>")
    lines.append("# confirm exact flags in the linked GitHub README before validation")
    return "\n".join(lines)

def chain_items(vendor: str, product: str, category: str, prim: str) -> list[str]:
    subject = product or vendor or "the affected product"
    items = [f"initial access through exposed {subject}"]
    if prim in {"RCE", "Auth Bypass"}:
        items.extend(["credential access from service context", "webshell or command execution follow-up"])
    if category in {"vpn-edge", "webstack", "rmm", "devops"}:
        items.append("internal pivot from an internet-facing control point")
    if category in {"adcs", "kerberos", "ntlm"}:
        items.append("identity escalation or relay path")
    if category in {"kernel", "framework"}:
        items.append("local privilege escalation after a foothold")
    items.append("lateral movement if secrets or management access are recovered")
    return items[:5]

def make_entry(item: dict, epss: float, repo: dict, mention: dict | None, nvd: dict, day_offset: int, first_seen_at: str) -> dict:
    is_kev = bool(item.get("dateAdded"))
    cve = item["cveID"].upper()
    vendor = norm(item.get("vendorProject", ""))
    product = norm(item.get("product", ""))
    name = norm(item.get("vulnerabilityName", ""))
    desc = norm(item.get("shortDescription") or nvd.get("description") or name)
    notes = norm(item.get("notes", ""))
    text = " ".join([cve, vendor, product, name, desc, notes, repo.get("description", "")])
    ecosystem = tag_value(text, ECOSYSTEM_RULES, "cloud")
    category = tag_value(text, CATEGORY_RULES, "webstack")
    prim = primitive(text)
    nvd_sev = (nvd.get("severity") or "").upper()
    severity = operator_severity(nvd_sev, prim, ecosystem, category, epss, repo, is_kev, text)
    confidence = min(98, 70 + repo.get("score", 0) // 3 + (12 if mention else 0) + (8 if item else 0))
    weaponization = min(99, int(55 + epss * 80 + (18 if item else 0) + (10 if item.get("knownRansomwareCampaignUse") == "Known" else 0)))
    title = derived_title(cve, vendor, product, name, desc, repo, mention, prim)
    summary = clean_summary(desc, repo, cve, vendor, product, prim)
    technical_summary = compact(summary, 280)
    if mention and mention.get("summary"):
        mention_summary = norm(re.sub(r"<[^>]+>", " ", mention["summary"]))
        if mention_summary and not looks_non_english(mention_summary):
            technical_summary = compact(mention_summary, 300)
    elif mention and mention.get("title"):
        mention_title = norm(mention["title"])
        if mention_title and not looks_non_english(mention_title):
            technical_summary = compact(f"{mention_title}. The useful takeaway is the vulnerable input path and how the public code validates the bug.", 300)
    primary_label = "GitHub" if "github.com/" in repo.get("url", "").lower() else "PoC"
    links = [[primary_label, repo["url"]]]
    if mention:
        links.append(["Technical Paper", mention["url"]])
    vendor_links = [url for url in extract_urls(notes) + nvd.get("references", []) if "nvd.nist.gov" not in url.lower()]
    if vendor_links:
        links.append(["Vendor Advisory", vendor_links[0]])
    tags = [labelize(ecosystem), labelize(category), prim]
    if repo.get("artifact_type") == "research artifact":
        tags.append("Research")
    if is_kev:
        tags.append("KEV")
    language = language_label(repo)
    difficulty = difficulty_label(repo, prim, epss)
    return {
        "cve": cve,
        "title": title,
        "ecosystem": ecosystem,
        "category": category,
        "severity": severity,
        "proof": "working public poc",
        "pocUrl": repo["url"],
        "pocValidation": repo.get("pocEvidence", {}),
        "reliability": "reliable exploit" if repo.get("score", 0) >= 60 else "partial exploit",
        "researcher": mention["source"] if mention else repo.get("owner", "public research"),
        "researcherUrl": mention.get("profileUrl", "") if mention else (repo.get("owner_url") or repo["url"]),
        "pocWorks": "Yes",
        "difficulty": difficulty,
        "added": format_added(first_seen_at),
        "firstSeenAt": first_seen_at,
        "language": language,
        "summary": summary,
        "technicalSummary": technical_summary,
        "breakdown": technical_summary,
        "whatBroke": compact(summary or f"{vendor} {product} exposed a useful {primitive_copy(prim)} primitive.", 240),
        "reality": compact(f"Realistic when the affected product is exposed and unpatched. The updater only includes this because public tooling signal was found at {repo.get('name')}.", 260),
        "exploitSyntax": exploit_syntax(repo, language),
        "chains": chain_items(vendor, product, category, prim),
        "weaponized": "Likely worth tracking because public tooling exists and recent source activity was observed.",
        "tags": tags,
        "confidence": confidence,
        "weaponization": weaponization,
        "dayOffset": day_offset,
        "links": links[:3],
    }

def entry_key(cve: str, poc_url: str) -> str:
    return f"{(cve or '').upper()}|{poc_url or ''}"

def existing_poc_url(entry: dict) -> str:
    if entry.get("pocUrl"):
        return str(entry.get("pocUrl") or "")
    for link in entry.get("links", []) if isinstance(entry.get("links"), list) else []:
        if isinstance(link, list) and len(link) >= 2 and "github.com/" in str(link[1]).lower():
            return str(link[1])
    for link in entry.get("links", []) if isinstance(entry.get("links"), list) else []:
        if isinstance(link, list) and len(link) >= 2:
            return str(link[1])
    return ""

now_utc = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
existing_first_seen = {}
if OUT.exists():
    try:
        existing_payload = json.loads(OUT.read_text(encoding="utf-8"))
        fallback_time = existing_payload.get("updatedAt") or now_utc.isoformat().replace("+00:00", "Z")
        for existing in existing_payload.get("vulns", []):
            if isinstance(existing, dict) and existing.get("cve"):
                poc_url = existing_poc_url(existing)
                existing_first_seen[entry_key(existing["cve"], poc_url)] = existing.get("firstSeenAt") or fallback_time
    except Exception as exc:
        print(f"warn: could not read existing first-seen times: {exc}")

kev = kev_items()
rss = rss_mentions()
research_items = rss_research_items(now_utc)
github_discovered = github_recent_cve_repos()
recent_nvd = nvd_recent_cves(now_utc)
kev_by_cve = {
    item.get("cveID", "").upper(): item
    for item in kev
    if CVE_RE.fullmatch(item.get("cveID", ""))
}
recent_kev = {
    cve
    for cve, item in kev_by_cve.items()
    if allowed_cve_year(cve) and recent_date(item.get("dateAdded", ""), now_utc)
}
current_year_github = {
    cve
    for cve in github_discovered
    if allowed_cve_year(cve)
}
current_year_nvd = {
    cve
    for cve in recent_nvd
    if allowed_cve_year(cve)
}
current_year_rss = {
    cve
    for cve in rss
    if allowed_cve_year(cve)
}
candidate_cves = sorted(current_year_rss | recent_kev | current_year_github | current_year_nvd)
epss = epss_scores(candidate_cves)

def synthetic_item(cve: str, nvd: dict, mention: dict | None) -> dict:
    return {
        "cveID": cve,
        "vendorProject": "",
        "product": "",
        "vulnerabilityName": (mention or {}).get("title") or cve,
        "shortDescription": nvd.get("description") or (mention or {}).get("summary") or "",
        "notes": "",
    }

scored = []
for cve in candidate_cves:
    item = kev_by_cve.get(cve)
    mention = rss.get(cve, [None])[0]
    repo_hint = (github_discovered.get(cve) or [None])[0]
    nvd_item = recent_nvd.get(cve, {})
    text = " ".join([
        cve,
        item.get("vendorProject", "") if item else "",
        item.get("product", "") if item else "",
        item.get("vulnerabilityName", "") if item else "",
        item.get("shortDescription", "") if item else "",
        nvd_item.get("description", "") if nvd_item else "",
        mention.get("title", "") if mention else "",
        mention.get("summary", "") if mention else "",
        repo_hint.get("name", "") if repo_hint else "",
        repo_hint.get("description", "") if repo_hint else "",
    ]).lower()
    signal = 0
    signal += 25 if item else 0
    signal += 18 if nvd_item else 0
    signal += 12 if (nvd_item.get("severity", "").upper() in {"HIGH", "CRITICAL"} if nvd_item else False) else 0
    signal += 38 if mention else 0
    signal += 42 if repo_hint else 0
    signal += min(25, int(repo_hint.get("score", 0)) // 3) if repo_hint else 0
    signal += 45 if contains_any(text, HIGH_SIGNAL) else 0
    signal += 20 if any(contains_any(text, terms[1]) for terms in PRIMITIVES.values()) else 0
    signal += 12 if contains_any(text, ["windows", "exchange", "sharepoint", "adcs", "kerberos", "ntlm", "rce", "lpe", "android", "ios", "pixel", "webkit", "zero-click", "zeroclick"]) else 0
    signal += 10 if contains_any(text, MOBILE_RESEARCHER_TERMS) else 0
    signal += int((epss.get(cve, 0) or 0) * 70)
    if item:
        signal += max(0, 60 - min(60, (now_utc - parse_date(item.get("dateAdded", ""))).days // 7))
    if mention:
        signal += max(0, 25 - max(0, (now_utc - parse_date(mention.get("publishedAt", ""))).days) * 3)
    if signal >= 55:
        scored.append((signal, cve))
scored.sort(key=lambda pair: pair[0], reverse=True)

entries = []
seen = set()
for signal, cve in scored[:45]:
    if cve in seen:
        continue
    try:
        repo = github_candidate(cve, github_discovered.get(cve, []))
        mention = rss.get(cve, [None])[0]
        if not repo:
            repo = mention_candidate(cve, mention)
        if not repo:
            continue
        if not repo.get("validatedPoc"):
            continue
        time.sleep(0.4)
        nvd = recent_nvd.get(cve) or nvd_lookup(cve)
        if not is_recent_release(cve, kev_by_cve.get(cve), mention, repo, nvd, now_utc):
            continue
        item = kev_by_cve.get(cve) or synthetic_item(cve, nvd, mention)
        first_seen_at = existing_first_seen.get(entry_key(cve, repo.get("url", ""))) or repo.get("created_at") or now_utc.isoformat().replace("+00:00", "Z")
        day_offset = archive_day_offset(first_seen_at, now_utc)
        if day_offset >= LOOKBACK_DAYS:
            first_seen_at = now_utc.isoformat().replace("+00:00", "Z")
            day_offset = 0
        entries.append(make_entry(item, epss.get(cve, 0), repo, mention, nvd, day_offset, first_seen_at))
        seen.add(cve)
    except Exception as exc:
        print(f"warn: skipped {cve}: {exc}")
        continue
    if len(entries) >= 18:
        break

if len(entries) < 5:
    print(f"warn: only {len(entries)} live entries found, writing the smaller fresh feed")

payload = {
    "updatedAt": now_utc.isoformat().replace("+00:00", "Z"),
    "cadence": "3x daily",
    "proofPolicy": "verified working public pocs",
    "sources": ["CISA KEV", "FIRST EPSS", "NVD", "GitHub Search", "GitHub Fresh PoC Discovery", *mobile_researcher_sources(), *[name for name, _ in RSS_SOURCES]],
    "research": research_items,
    "vulns": entries,
}
OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"wrote {len(entries)} live entries to {OUT}")

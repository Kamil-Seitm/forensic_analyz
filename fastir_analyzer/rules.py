from __future__ import annotations

import ipaddress
import os
import socket
from functools import lru_cache
from typing import Dict, Iterable, List, Optional

import requests

from .io import JsonLike


def _is_suspicious_path(path: str | None) -> bool:
    """Проверить, указывает ли путь на временные или нетипичные каталоги."""
    if not path:
        return True
    lowered = path.lower()
    return any(
        part in lowered
        for part in ["\\temp\\", "/tmp/", ":\\users\\public\\", "appdata\\local\\temp", "\\recycle"]
    )


def analyze_autoruns(entries: Iterable[JsonLike]) -> List[Dict[str, str]]:
    """Выявить записи автозапуска, у которых бинарник лежит в подозрительном месте."""
    findings: List[Dict[str, str]] = []
    for entry in entries:
        image = entry.get("ImagePath") or entry.get("Path") or entry.get("Image")
        location = entry.get("Location") or entry.get("Key")
        if _is_suspicious_path(image):
            findings.append(
                {
                    "category": "autorun",
                    "reason": "Autorun entry uses suspicious path",
                    "path": str(image or "<missing>"),
                    "location": str(location or "<unknown>"),
                }
            )
    return findings


def analyze_services(entries: Iterable[JsonLike]) -> List[Dict[str, str]]:
    """Найти сервисы, работающие из временных директорий или публичных профилей."""
    findings: List[Dict[str, str]] = []
    for entry in entries:
        image = entry.get("ImagePath") or entry.get("Path")
        name = entry.get("Name") or entry.get("ServiceName")
        if _is_suspicious_path(image):
            findings.append(
                {
                    "category": "service",
                    "reason": "Service binary located in temporary directory",
                    "path": str(image or "<missing>"),
                    "name": str(name or "<unknown>"),
                }
            )
    return findings


def extract_hostname(remote: str) -> str:
    """Вернуть хост/адрес без порта."""
    return remote.split(":", 1)[0].strip()


def query_whois(target: str, server: str) -> str:
    with socket.create_connection((server, 43), timeout=5) as sock:
        sock.sendall((target + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="ignore")


@lru_cache(maxsize=128)
def whois_lookup(target: str) -> Dict[str, str]:
    """Получить WHOIS-текст и выделить организацию/подозрительные хостинг-метки."""
    try:
        first = query_whois(target, "whois.iana.org")
        refer = next(
            (
                line.split(":", 1)[1].strip()
                for line in first.splitlines()
                if line.lower().startswith("refer:")
            ),
            None,
        )
        server = refer or "whois.arin.net"
        full = query_whois(target, server)
    except Exception:
        return {}

    org_line = next(
        (
            line.split(":", 1)[1].strip()
            for line in full.splitlines()
            if line.lower().startswith("orgname") or line.lower().startswith("org:")
        ),
        "",
    )
    hosting_markers = ["vds", "vps", "virtual", "cloud", "hosting", "data center"]
    is_vds = any(marker in full.lower() for marker in hosting_markers)
    note = "Возможно VDS/VPS хостинг" if is_vds else ""
    return {"org": org_line, "raw": full, "note": note}


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


@lru_cache(maxsize=128)
def virustotal_lookup(target: str) -> Optional[str]:
    """Запросить VirusTotal и вернуть краткий статус."""
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return "VT API key missing"

    entity_type = "domains" if not _looks_like_ip(target) else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{entity_type}/{target}"
    try:
        resp = requests.get(url, headers={"x-apikey": api_key}, timeout=10)
        if resp.status_code != 200:
            return f"VT error {resp.status_code}"
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
    except Exception:
        return "VT request failed"
    if malicious or suspicious:
        return f"Flagged: malicious={malicious}, suspicious={suspicious}"
    return "Clean (no detections)"


def enrich_remote(remote: str) -> Dict[str, str]:
    """Собрать справку по адресу: WHOIS + VirusTotal."""
    hostname = extract_hostname(remote)
    info: Dict[str, str] = whois_lookup(hostname)
    vt_status = virustotal_lookup(hostname)
    if vt_status:
        info["vt_status"] = vt_status
    return info


def analyze_network(entries: Iterable[JsonLike]) -> List[Dict[str, str]]:
    """Отметить внешние соединения и обогатить их WHOIS/VT справкой."""
    findings: List[Dict[str, str]] = []
    for entry in entries:
        remote = (
            entry.get("ForeignAddress")
            or entry.get("RemoteAddress")
            or entry.get("Remote")
        )
        process = entry.get("Process") or entry.get("ProcessName")
        if not remote:
            continue
        try:
            address = remote.split(":")[0]
            ip = ipaddress.ip_address(address)
        except Exception:
            continue
        if ip.is_private or ip.is_loopback:
            continue
        enrichment = enrich_remote(remote)
        findings.append(
            {
                "category": "network",
                "reason": "Connection to external address",
                "remote": str(remote),
                "process": str(process or "<unknown>"),
                "whois_org": enrichment.get("org", ""),
                "whois_note": enrichment.get("note", ""),
                "virustotal": enrichment.get("vt_status", ""),
            }
        )
    return findings


def analyze_processes(entries: Iterable[JsonLike]) -> List[Dict[str, str]]:
    """Искать PowerShell-процессы, обращающиеся во внешнюю сеть."""
    findings: List[Dict[str, str]] = []
    for entry in entries:
        name = str(entry.get("Name") or entry.get("Image") or "")
        parent = str(entry.get("Parent") or entry.get("ParentPID") or "")
        cmdline = str(entry.get("CommandLine") or entry.get("CmdLine") or "")
        if "powershell" in name.lower() and "http" in cmdline.lower():
            findings.append(
                {
                    "category": "process",
                    "reason": "PowerShell executed with external network target",
                    "name": name,
                    "cmdline": cmdline,
                    "parent": parent,
                }
            )
    return findings


ANALYZERS = {
    "autoruns": analyze_autoruns,
    "services": analyze_services,
    "network": analyze_network,
    "process": analyze_processes,
    "processes": analyze_processes,
}


def run_all_rules(artifacts: Dict[str, List[JsonLike]]) -> List[Dict[str, str]]:
    """Запустить все зарегистрированные анализаторы для имеющихся артефактов."""
    findings: List[Dict[str, str]] = []
    for key, analyzer in ANALYZERS.items():
        entries = artifacts.get(key, [])
        if not entries:
            continue
        findings.extend(analyzer(entries))
    return findings

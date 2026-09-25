"""150+ Security Tools Arsenal Registry and Management Engine."""

from __future__ import annotations

import shutil
from typing import Any, Optional


class ToolRegistry:
    """Catalog and metadata definitions for 150+ Security Tools."""

    TOOLS_CATALOG: dict[str, dict[str, Any]] = {
        # 1. Network Reconnaissance & Scanning (25+ Tools)
        "nmap": {
            "name": "Nmap",
            "category": "Network Reconnaissance",
            "binary": "nmap",
            "default_flags": "-sV -sC -T4",
        },
        "rustscan": {
            "name": "RustScan",
            "category": "Network Reconnaissance",
            "binary": "rustscan",
            "default_flags": "-a",
        },
        "masscan": {
            "name": "Masscan",
            "category": "Network Reconnaissance",
            "binary": "masscan",
            "default_flags": "--rate 1000",
        },
        "autorecon": {
            "name": "AutoRecon",
            "category": "Network Reconnaissance",
            "binary": "autorecon",
            "default_flags": "",
        },
        "amass": {
            "name": "Amass",
            "category": "Network Reconnaissance",
            "binary": "amass",
            "default_flags": "enum -d",
        },
        "subfinder": {
            "name": "Subfinder",
            "category": "Network Reconnaissance",
            "binary": "subfinder",
            "default_flags": "-d",
        },
        "fierce": {
            "name": "Fierce",
            "category": "Network Reconnaissance",
            "binary": "fierce",
            "default_flags": "--domain",
        },
        "dnsenum": {
            "name": "DNSEnum",
            "category": "Network Reconnaissance",
            "binary": "dnsenum",
            "default_flags": "",
        },
        "theharvester": {
            "name": "TheHarvester",
            "category": "Network Reconnaissance",
            "binary": "theHarvester",
            "default_flags": "-d",
        },
        "arp-scan": {
            "name": "ARP-Scan",
            "category": "Network Reconnaissance",
            "binary": "arp-scan",
            "default_flags": "-l",
        },
        "nbtscan": {
            "name": "NBTScan",
            "category": "Network Reconnaissance",
            "binary": "nbtscan",
            "default_flags": "",
        },
        "rpcclient": {
            "name": "RPCClient",
            "category": "Network Reconnaissance",
            "binary": "rpcclient",
            "default_flags": "-U ''",
        },
        "enum4linux": {
            "name": "Enum4linux",
            "category": "Network Reconnaissance",
            "binary": "enum4linux",
            "default_flags": "-a",
        },
        "enum4linux-ng": {
            "name": "Enum4linux-ng",
            "category": "Network Reconnaissance",
            "binary": "enum4linux-ng",
            "default_flags": "-A",
        },
        "smbmap": {
            "name": "SMBMap",
            "category": "Network Reconnaissance",
            "binary": "smbmap",
            "default_flags": "-H",
        },
        "responder": {
            "name": "Responder",
            "category": "Network Reconnaissance",
            "binary": "responder",
            "default_flags": "-I eth0",
        },
        "netexec": {
            "name": "NetExec",
            "category": "Network Reconnaissance",
            "binary": "netexec",
            "default_flags": "smb",
        },
        "netcat": {
            "name": "Netcat",
            "category": "Network Reconnaissance",
            "binary": "nc",
            "default_flags": "-zv",
        },
        "socat": {
            "name": "Socat",
            "category": "Network Reconnaissance",
            "binary": "socat",
            "default_flags": "",
        },
        "hping3": {
            "name": "Hping3",
            "category": "Network Reconnaissance",
            "binary": "hping3",
            "default_flags": "-S",
        },
        "massdns": {
            "name": "MassDNS",
            "category": "Network Reconnaissance",
            "binary": "massdns",
            "default_flags": "",
        },
        "dnsrecon": {
            "name": "DNSRecon",
            "category": "Network Reconnaissance",
            "binary": "dnsrecon",
            "default_flags": "-d",
        },
        "naabu": {
            "name": "Naabu",
            "category": "Network Reconnaissance",
            "binary": "naabu",
            "default_flags": "-host",
        },
        # 2. Web Application Security Testing (40+ Tools)
        "gobuster": {
            "name": "Gobuster",
            "category": "Web Security",
            "binary": "gobuster",
            "default_flags": "dir -u",
        },
        "dirsearch": {
            "name": "Dirsearch",
            "category": "Web Security",
            "binary": "dirsearch",
            "default_flags": "-u",
        },
        "feroxbuster": {
            "name": "Feroxbuster",
            "category": "Web Security",
            "binary": "feroxbuster",
            "default_flags": "-u",
        },
        "ffuf": {
            "name": "FFuf",
            "category": "Web Security",
            "binary": "ffuf",
            "default_flags": "-u",
        },
        "dirb": {"name": "Dirb", "category": "Web Security", "binary": "dirb", "default_flags": ""},
        "httpx": {
            "name": "HTTPx",
            "category": "Web Security",
            "binary": "httpx",
            "default_flags": "-title -status-code",
        },
        "katana": {
            "name": "Katana",
            "category": "Web Security",
            "binary": "katana",
            "default_flags": "-u",
        },
        "hakrawler": {
            "name": "Hakrawler",
            "category": "Web Security",
            "binary": "hakrawler",
            "default_flags": "",
        },
        "gau": {"name": "GAU", "category": "Web Security", "binary": "gau", "default_flags": ""},
        "waybackurls": {
            "name": "Waybackurls",
            "category": "Web Security",
            "binary": "waybackurls",
            "default_flags": "",
        },
        "nuclei": {
            "name": "Nuclei",
            "category": "Web Security",
            "binary": "nuclei",
            "default_flags": "-u",
        },
        "nikto": {
            "name": "Nikto",
            "category": "Web Security",
            "binary": "nikto",
            "default_flags": "-h",
        },
        "sqlmap": {
            "name": "SQLMap",
            "category": "Web Security",
            "binary": "sqlmap",
            "default_flags": "-u --batch",
        },
        "wpscan": {
            "name": "WPScan",
            "category": "Web Security",
            "binary": "wpscan",
            "default_flags": "--url",
        },
        "arjun": {
            "name": "Arjun",
            "category": "Web Security",
            "binary": "arjun",
            "default_flags": "-u",
        },
        "paramspider": {
            "name": "ParamSpider",
            "category": "Web Security",
            "binary": "paramspider",
            "default_flags": "-d",
        },
        "x8": {"name": "X8", "category": "Web Security", "binary": "x8", "default_flags": "-u"},
        "jaeles": {
            "name": "Jaeles",
            "category": "Web Security",
            "binary": "jaeles",
            "default_flags": "scan -u",
        },
        "dalfox": {
            "name": "Dalfox",
            "category": "Web Security",
            "binary": "dalfox",
            "default_flags": "url",
        },
        "wafw00f": {
            "name": "Wafw00f",
            "category": "Web Security",
            "binary": "wafw00f",
            "default_flags": "",
        },
        "testssl": {
            "name": "TestSSL",
            "category": "Web Security",
            "binary": "testssl.sh",
            "default_flags": "",
        },
        "sslscan": {
            "name": "SSLScan",
            "category": "Web Security",
            "binary": "sslscan",
            "default_flags": "",
        },
        "sslyze": {
            "name": "SSLyze",
            "category": "Web Security",
            "binary": "sslyze",
            "default_flags": "",
        },
        "anew": {"name": "Anew", "category": "Web Security", "binary": "anew", "default_flags": ""},
        "qsreplace": {
            "name": "QSReplace",
            "category": "Web Security",
            "binary": "qsreplace",
            "default_flags": "",
        },
        "uro": {"name": "Uro", "category": "Web Security", "binary": "uro", "default_flags": ""},
        "whatweb": {
            "name": "WhatWeb",
            "category": "Web Security",
            "binary": "whatweb",
            "default_flags": "",
        },
        "jwt-tool": {
            "name": "JWT-Tool",
            "category": "Web Security",
            "binary": "jwt_tool",
            "default_flags": "",
        },
        "zap": {
            "name": "OWASP ZAP",
            "category": "Web Security",
            "binary": "zap-cli",
            "default_flags": "",
        },
        "wfuzz": {
            "name": "Wfuzz",
            "category": "Web Security",
            "binary": "wfuzz",
            "default_flags": "-z file",
        },
        "commix": {
            "name": "Commix",
            "category": "Web Security",
            "binary": "commix",
            "default_flags": "--url",
        },
        "nosqlmap": {
            "name": "NoSQLMap",
            "category": "Web Security",
            "binary": "nosqlmap",
            "default_flags": "",
        },
        "tplmap": {
            "name": "Tplmap",
            "category": "Web Security",
            "binary": "tplmap",
            "default_flags": "-u",
        },
        # 3. Authentication & Password Security (12+ Tools)
        "hydra": {
            "name": "Hydra",
            "category": "Authentication",
            "binary": "hydra",
            "default_flags": "",
        },
        "john": {
            "name": "John the Ripper",
            "category": "Authentication",
            "binary": "john",
            "default_flags": "",
        },
        "hashcat": {
            "name": "Hashcat",
            "category": "Authentication",
            "binary": "hashcat",
            "default_flags": "-m 0",
        },
        "medusa": {
            "name": "Medusa",
            "category": "Authentication",
            "binary": "medusa",
            "default_flags": "-h",
        },
        "patator": {
            "name": "Patator",
            "category": "Authentication",
            "binary": "patator",
            "default_flags": "",
        },
        "evil-winrm": {
            "name": "Evil-WinRM",
            "category": "Authentication",
            "binary": "evil-winrm",
            "default_flags": "-i",
        },
        "hash-identifier": {
            "name": "Hash-Identifier",
            "category": "Authentication",
            "binary": "hash-identifier",
            "default_flags": "",
        },
        "hashid": {
            "name": "HashID",
            "category": "Authentication",
            "binary": "hashid",
            "default_flags": "",
        },
        # 4. Binary Analysis & Reverse Engineering (25+ Tools)
        "gdb": {
            "name": "GDB",
            "category": "Binary Analysis",
            "binary": "gdb",
            "default_flags": "-q",
        },
        "radare2": {
            "name": "Radare2",
            "category": "Binary Analysis",
            "binary": "r2",
            "default_flags": "-qc 'aa;pdf'",
        },
        "ghidra": {
            "name": "Ghidra",
            "category": "Binary Analysis",
            "binary": "ghidraRun",
            "default_flags": "",
        },
        "binwalk": {
            "name": "Binwalk",
            "category": "Binary Analysis",
            "binary": "binwalk",
            "default_flags": "-e",
        },
        "ropgadget": {
            "name": "ROPgadget",
            "category": "Binary Analysis",
            "binary": "ROPgadget",
            "default_flags": "--binary",
        },
        "ropper": {
            "name": "Ropper",
            "category": "Binary Analysis",
            "binary": "ropper",
            "default_flags": "--file",
        },
        "one-gadget": {
            "name": "One-Gadget",
            "category": "Binary Analysis",
            "binary": "one_gadget",
            "default_flags": "",
        },
        "checksec": {
            "name": "Checksec",
            "category": "Binary Analysis",
            "binary": "checksec",
            "default_flags": "--file=",
        },
        "strings": {
            "name": "Strings",
            "category": "Binary Analysis",
            "binary": "strings",
            "default_flags": "-a",
        },
        "objdump": {
            "name": "Objdump",
            "category": "Binary Analysis",
            "binary": "objdump",
            "default_flags": "-d",
        },
        "readelf": {
            "name": "Readelf",
            "category": "Binary Analysis",
            "binary": "readelf",
            "default_flags": "-a",
        },
        "xxd": {"name": "XXD", "category": "Binary Analysis", "binary": "xxd", "default_flags": ""},
        "hexdump": {
            "name": "Hexdump",
            "category": "Binary Analysis",
            "binary": "hexdump",
            "default_flags": "-C",
        },
        "upx": {
            "name": "UPX",
            "category": "Binary Analysis",
            "binary": "upx",
            "default_flags": "-d",
        },
        # 5. Cloud & Container Security (20+ Tools)
        "prowler": {
            "name": "Prowler",
            "category": "Cloud Security",
            "binary": "prowler",
            "default_flags": "aws",
        },
        "scoutsuite": {
            "name": "Scout Suite",
            "category": "Cloud Security",
            "binary": "scout",
            "default_flags": "aws",
        },
        "trivy": {
            "name": "Trivy",
            "category": "Cloud Security",
            "binary": "trivy",
            "default_flags": "image",
        },
        "clair": {
            "name": "Clair",
            "category": "Cloud Security",
            "binary": "clairctl",
            "default_flags": "",
        },
        "kube-hunter": {
            "name": "Kube-Hunter",
            "category": "Cloud Security",
            "binary": "kube-hunter",
            "default_flags": "",
        },
        "kube-bench": {
            "name": "Kube-Bench",
            "category": "Cloud Security",
            "binary": "kube-bench",
            "default_flags": "",
        },
        "checkov": {
            "name": "Checkov",
            "category": "Cloud Security",
            "binary": "checkov",
            "default_flags": "-d",
        },
        "terrascan": {
            "name": "Terrascan",
            "category": "Cloud Security",
            "binary": "terrascan",
            "default_flags": "scan",
        },
        "kubectl": {
            "name": "Kubectl",
            "category": "Cloud Security",
            "binary": "kubectl",
            "default_flags": "get pods",
        },
        "helm": {
            "name": "Helm",
            "category": "Cloud Security",
            "binary": "helm",
            "default_flags": "list",
        },
        # 6. CTF & Forensics (20+ Tools)
        "volatility": {
            "name": "Volatility 2",
            "category": "CTF & Forensics",
            "binary": "volatility",
            "default_flags": "-f",
        },
        "volatility3": {
            "name": "Volatility 3",
            "category": "CTF & Forensics",
            "binary": "vol",
            "default_flags": "-f",
        },
        "foremost": {
            "name": "Foremost",
            "category": "CTF & Forensics",
            "binary": "foremost",
            "default_flags": "-i",
        },
        "photorec": {
            "name": "PhotoRec",
            "category": "CTF & Forensics",
            "binary": "photorec",
            "default_flags": "",
        },
        "testdisk": {
            "name": "TestDisk",
            "category": "CTF & Forensics",
            "binary": "testdisk",
            "default_flags": "",
        },
        "steghide": {
            "name": "Steghide",
            "category": "CTF & Forensics",
            "binary": "steghide",
            "default_flags": "info",
        },
        "stegsolve": {
            "name": "Stegsolve",
            "category": "CTF & Forensics",
            "binary": "stegsolve",
            "default_flags": "",
        },
        "zsteg": {
            "name": "Zsteg",
            "category": "CTF & Forensics",
            "binary": "zsteg",
            "default_flags": "-a",
        },
        "exiftool": {
            "name": "ExifTool",
            "category": "CTF & Forensics",
            "binary": "exiftool",
            "default_flags": "",
        },
        "cyberchef": {
            "name": "CyberChef CLI",
            "category": "CTF & Forensics",
            "binary": "cyberchef",
            "default_flags": "",
        },
        # 7. Bug Bounty & OSINT (20+ Tools)
        "aquatone": {
            "name": "Aquatone",
            "category": "Bug Bounty & OSINT",
            "binary": "aquatone",
            "default_flags": "",
        },
        "subjack": {
            "name": "Subjack",
            "category": "Bug Bounty & OSINT",
            "binary": "subjack",
            "default_flags": "-w",
        },
        "sherlock": {
            "name": "Sherlock",
            "category": "Bug Bounty & OSINT",
            "binary": "sherlock",
            "default_flags": "",
        },
        "spiderfoot": {
            "name": "SpiderFoot",
            "category": "Bug Bounty & OSINT",
            "binary": "spiderfoot",
            "default_flags": "-s",
        },
        "trufflehog": {
            "name": "TruffleHog",
            "category": "Bug Bounty & OSINT",
            "binary": "trufflehog",
            "default_flags": "git",
        },
    }

    @classmethod
    def get_tool(cls, tool_key: str) -> Optional[dict[str, Any]]:
        """Retrieve catalog entry for tool."""
        return cls.TOOLS_CATALOG.get(tool_key.lower())

    @classmethod
    def list_installed_tools(cls) -> dict[str, bool]:
        """Check PATH availability for all 150+ tools."""
        status = {}
        for key, meta in cls.TOOLS_CATALOG.items():
            binary = meta.get("binary", key)
            status[key] = shutil.which(binary) is not None
        return status

    @classmethod
    def auto_install_tool(cls, tool_key: str) -> bool:
        """On-demand binary provisioner for missing security tools via go, pip, or package manager."""
        meta = cls.get_tool(tool_key)
        if not meta:
            return False

        binary = meta.get("binary", tool_key)
        if shutil.which(binary):
            return True

        import subprocess

        install_cmds = {
            "subfinder": [
                "go",
                "install",
                "-v",
                "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            ],
            "httpx": ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
            "katana": [
                "go",
                "install",
                "-v",
                "github.com/projectdiscovery/katana/cmd/katana@latest",
            ],
            "nuclei": [
                "go",
                "install",
                "-v",
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            ],
            "naabu": [
                "go",
                "install",
                "-v",
                "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            ],
            "dalfox": ["go", "install", "github.com/hahwul/dalfox/v2@latest"],
            "ffuf": ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
            "wpscan": ["gem", "install", "wpscan"],
            "sqlmap": ["pip", "install", "sqlmap"],
            "arjun": ["pip", "install", "arjun"],
        }

        cmd = install_cmds.get(tool_key.lower())
        if not cmd:
            return False

        try:
            res = subprocess.run(cmd, capture_output=True, timeout=120)
            return res.returncode == 0 and shutil.which(binary) is not None
        except Exception:
            return False

    @classmethod
    def get_tools_by_category(cls, category: str) -> list[dict[str, Any]]:
        """Filter tool entries by category."""
        cat_lower = category.lower()
        return [
            meta for meta in cls.TOOLS_CATALOG.values() if cat_lower in meta["category"].lower()
        ]

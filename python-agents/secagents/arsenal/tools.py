"""Tool Output Parsers: Structured XML/JSON normalizers for security tool outputs."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List


class ToolOutputParser:
    """Parses raw stdout/stderr/XML/JSON tool outputs into structured finding signals."""

    @staticmethod
    def parse_nmap_xml(xml_content: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output into open ports and service dictionary."""
        results = []
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                ip = ""
                addr_node = host.find("address")
                if addr_node is not None:
                    ip = addr_node.get("addr", "")

                for port in host.findall(".//port"):
                    state_node = port.find("state")
                    if state_node is not None and state_node.get("state") == "open":
                        port_id = int(port.get("portid", 0))
                        service_node = port.find("service")
                        service_name = (
                            service_node.get("name", "unknown")
                            if service_node is not None
                            else "unknown"
                        )
                        product = (
                            service_node.get("product", "") if service_node is not None else ""
                        )

                        results.append(
                            {
                                "type": "nmap_open_port",
                                "ip": ip,
                                "port": port_id,
                                "service": service_name,
                                "product": product,
                            }
                        )
        except Exception:
            pass
        return results

    @staticmethod
    def parse_nuclei_json(json_lines: str) -> List[Dict[str, Any]]:
        """Parse line-delimited JSON output from Nuclei scanner."""
        results = []
        for line in json_lines.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                results.append(
                    {
                        "type": "nuclei_finding",
                        "template_id": data.get("template-id", ""),
                        "name": info.get("name", ""),
                        "severity": info.get("severity", "info"),
                        "matched_at": data.get("matched-at", ""),
                        "cwe": info.get("classification", {}).get("cwe-id", []),
                    }
                )
            except Exception:
                continue
        return results

    @staticmethod
    def parse_sqlmap_stdout(stdout: str) -> List[Dict[str, Any]]:
        """Parse SQLMap stdout for injected parameters and DBMS types."""
        results = []
        if "is vulnerable" in stdout or "DBMS:" in stdout:
            results.append(
                {
                    "type": "sqli_confirmed",
                    "tool": "sqlmap",
                    "details": "SQLMap confirmed injection vulnerability in target parameter",
                    "severity": "critical",
                }
            )
        return results

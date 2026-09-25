"""Model Context Protocol (MCP) Server for SecAgent."""

from __future__ import annotations

import json
import sys
import logging
import asyncio
from typing import Any, Dict

logger = logging.getLogger("secagents.mcp_server")


class MCPServer:
    """JSON-RPC 2.0 stdio Model Context Protocol (MCP) Server for SecAgent."""

    def __init__(self):
        self.tools = {
            "secagent_scan": self._handle_scan,
            "secagent_verify_poc": self._handle_verify_poc,
            "secagent_list_tools": self._handle_list_tools,
            "secagent_get_target_dna": self._handle_get_target_dna,
        }

    def _handle_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from secagents.infra.scope import enforce_scope
        from secagents.pipeline.runner import ScanPipeline

        target = str(args.get("target", "")).strip()
        enforce_scope(target)
        depth = args.get("depth", "standard")
        if depth not in {"quick", "standard", "deep"}:
            raise ValueError("depth must be quick, standard, or deep")
        workers = int(args.get("workers", 4))
        if not 1 <= workers <= 32:
            raise ValueError("workers must be between 1 and 32")
        pipeline = ScanPipeline(target=target, depth=depth, workers=workers)
        result = asyncio.run(pipeline.run())
        return {
            "status": "incomplete"
            if result.get("phases", {}).get("armada_failures")
            or result.get("budget", {}).get("termination_reason")
            else "completed",
            "target": target,
            "findings_count": len(result.get("findings", [])),
            "manual_leads_count": len(result.get("manual_leads", [])),
            "failures": result.get("phases", {}).get("armada_failures", []),
            "budget": result.get("budget", {}),
            "reports": result.get("reports", {}),
        }

    def _handle_verify_poc(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from secagents.operational.proof_capsule import ProofCapsule, ProofCapsuleReplayer
        from secagents.infra.scope import enforce_scope

        raw = args.get("capsule_json")
        if not raw:
            raise ValueError("capsule_json is required")
        capsule = ProofCapsule.from_json(raw if isinstance(raw, str) else json.dumps(raw))
        enforce_scope(capsule.target_url)
        verified, message = asyncio.run(ProofCapsuleReplayer().replay_async(capsule))
        return {"verified": verified, "message": message}

    def _handle_list_tools(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from secagents.arsenal.registry import ToolRegistry

        return {"tools": ToolRegistry.list_installed_tools()}

    def _handle_get_target_dna(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target = args.get("target", "")
        from secagents.core.aura_memory import AuraMemoryManager
        from secagents.infra.scope import enforce_scope

        enforce_scope(target)
        dna = AuraMemoryManager.get_instance().recall_target_dna(target)
        if dna is None:
            return {"target": target, "found": False}
        return {
            "target": dna.target,
            "found": True,
            "domain": dna.domain,
            "tech_stack": dna.tech_stack,
            "waf_signature": dna.waf_signature,
            "last_scanned": dna.last_scanned,
        }

    def process_request(self, request_json: str) -> str:
        """Parse JSON-RPC 2.0 request and compute response."""
        try:
            req = json.loads(request_json)
            req_id = req.get("id")
            method = req.get("method", "")
            params = req.get("params", {})

            if method == "initialize":
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "secagent", "version": "0.2.0"},
                        },
                        "id": req_id,
                    }
                )
            if method == "notifications/initialized":
                return ""
            if method == "ping":
                return json.dumps({"jsonrpc": "2.0", "result": {}, "id": req_id})

            if method == "tools/list":
                tool_list = [
                    {
                        "name": "secagent_scan",
                        "description": "Run an authorized SecAgent scan",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {"type": "string"},
                                "depth": {"type": "string", "enum": ["quick", "standard", "deep"]},
                                "workers": {"type": "integer", "minimum": 1, "maximum": 32},
                            },
                            "required": ["target"],
                        },
                    },
                    {
                        "name": "secagent_verify_poc",
                        "description": "Replay a proof capsule",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"capsule_json": {"type": "string"}},
                            "required": ["capsule_json"],
                        },
                    },
                    {
                        "name": "secagent_list_tools",
                        "description": "List installed security tools",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "secagent_get_target_dna",
                        "description": "Retrieve target memory",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"target": {"type": "string"}},
                            "required": ["target"],
                        },
                    },
                ]
                return json.dumps({"jsonrpc": "2.0", "result": {"tools": tool_list}, "id": req_id})

            if method == "tools/call":
                name = params.get("name")
                args = params.get("arguments", {})
                handler = self.tools.get(name)
                if handler:
                    try:
                        res = handler(args)
                    except (ValueError, PermissionError, RuntimeError) as exc:
                        return json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "result": {
                                    "isError": True,
                                    "content": [{"type": "text", "text": str(exc)}],
                                },
                                "id": req_id,
                            }
                        )
                    return json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "result": {"content": [{"type": "text", "text": json.dumps(res)}]},
                            "id": req_id,
                        }
                    )
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "error": {"code": -32601, "message": f"Method {name} not found"},
                        "id": req_id,
                    }
                )

            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Unsupported method {method}"},
                    "id": req_id,
                }
            )
        except Exception as e:
            return json.dumps(
                {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": None}
            )

    def run_stdio(self) -> None:
        """Run infinite stdio loop reading JSON-RPC lines."""
        for line in sys.stdin:
            if not line.strip():
                continue
            response = self.process_request(line)
            if response:
                sys.stdout.write(response + "\n")
                sys.stdout.flush()


def main():
    server = MCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()

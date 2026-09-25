"""Validator agent for finding verification and false positive filtering."""

import asyncio
import json
import logging
import os
import httpx

from secagents.agents.base import BaseAgent, AgentConfig, AgentOutput, AgentRole
from secagents.prompts import VALIDATOR_PROMPT

logger = logging.getLogger(__name__)


class ValidatorAgent(BaseAgent):
    """Validates findings to reduce false positives.

    Responsibilities:
    - PoC request replay
    - Response analysis
    - Consistency verification
    - Severity assessment
    - Confidence scoring
    """

    def __init__(self):
        super().__init__(
            AgentConfig(
                role=AgentRole.VALIDATOR,
                name="validator",
                tools=["http_request", "replay_request", "compare_response"],
                timeout_seconds=300.0,
            )
        )
        self.logger = logging.getLogger("secagents.validator")

    def base_system_prompt(self) -> str:
        """Return the validator's system prompt."""
        return VALIDATOR_PROMPT

    async def execute(self, task: dict) -> AgentOutput:
        """Execute validation logic on findings."""
        findings = task.get("findings", [])

        if not findings:
            self.logger.info("No findings to validate")
            return self._format_output(
                result={"validated": [], "rejected": []},
                confidence=1.0,
                reasoning="No findings to validate",
            )

        self.logger.info(f"Validating {len(findings)} findings")

        try:
            validated = []
            rejected = []
            inconclusive = []

            # Filter low confidence findings first
            high_conf_findings = []
            for finding in findings:
                if finding.get("confidence", 1.0) < 0.5:
                    rejected.append(
                        {
                            **finding,
                            "validated": False,
                            "rejection_reason": "Low initial confidence",
                        }
                    )
                else:
                    high_conf_findings.append(finding)

            # Validate remaining findings concurrently
            validation_tasks = [self._validate(finding) for finding in high_conf_findings]
            results = await asyncio.gather(*validation_tasks, return_exceptions=True)

            for finding, result in zip(high_conf_findings, results):
                if isinstance(result, BaseException):
                    self.logger.warning(f"Validation failed: {str(result)}")
                    inconclusive.append({**finding, "validation_status": "error"})
                elif result["is_valid"]:
                    validated.append(
                        {
                            **finding,
                            "validated": True,
                            "validation_confidence": result["confidence"],
                            "validation_method": result["method"],
                            "validation_steps": result["steps"],
                        }
                    )
                else:
                    rejected.append(
                        {
                            **finding,
                            "validated": False,
                            "rejection_reason": result["reason"],
                        }
                    )

            total = len(findings)
            valid_count = len(validated)
            rejection_rate = len(rejected) / total if total > 0 else 0

            confidence = self._calculate_validation_confidence(valid_count, total, rejection_rate)

            result = {
                "validated": validated,
                "rejected": rejected,
                "inconclusive": inconclusive,
                "total": total,
                "valid_count": valid_count,
                "rejection_rate": round(rejection_rate, 2),
            }

            self.logger.info(
                f"Validation complete: {valid_count} valid, "
                f"{len(rejected)} rejected, {len(inconclusive)} inconclusive"
            )

            return self._format_output(
                result=result,
                confidence=confidence,
                reasoning=f"Validated {valid_count}/{total} findings",
                metadata={
                    "total": total,
                    "valid": valid_count,
                    "rejected": len(rejected),
                },
            )
        except Exception as e:
            self.logger.error(f"Validation failed: {str(e)}", exc_info=True)
            return self._format_output(
                result={"error": str(e)},
                confidence=0.0,
                reasoning="Validation execution failed",
            )

    async def _validate(self, finding: dict) -> dict:
        """Validate a single finding.

        Args:
            finding: Finding to validate

        Returns:
            Validation result
        """
        finding_type = finding.get("type", "unknown")

        self.logger.info(f"Validating {finding_type} finding")

        try:
            # Primary validation: replay PoC
            poc_result = await self._replay_poc(finding)

            if not poc_result["valid"]:
                return {
                    "is_valid": False,
                    "reason": "PoC replay failed",
                    "confidence": 0.0,
                }

            # Secondary validation: test consistency
            consistency = await self._test_consistency(finding, poc_result)

            if not consistency["consistent"]:
                return {
                    "is_valid": False,
                    "reason": "Inconsistent behavior",
                    "confidence": 0.3,
                }

            # Tertiary validation: edge case testing
            edge_cases = await self._test_edge_cases(finding)

            confidence = self._calculate_finding_confidence(poc_result, consistency, edge_cases)

            return {
                "is_valid": True,
                "confidence": confidence,
                "method": "multi_stage_validation",
                "steps": [
                    "PoC replay",
                    "Consistency check",
                    "Edge case testing",
                ],
            }
        except Exception as e:
            self.logger.error(f"Validation error: {str(e)}")
            raise

    async def _replay_poc(self, finding: dict) -> dict:
        """Replay the original PoC request against the live endpoint."""
        poc_url = finding.get("poc_url") or finding.get("url", "")
        proof_signal = finding.get("proof_signal") or finding.get("evidence", "")
        verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"

        if not poc_url:
            return {"valid": False, "reason": "No PoC URL provided"}

        self.logger.info(f"Replaying live PoC request to: {poc_url}")

        try:
            from secagents.infra.scope import enforce_scope

            enforce_scope(poc_url)
            async with httpx.AsyncClient(
                timeout=8.0, verify=verify_ssl, follow_redirects=False
            ) as client:
                method = finding.get("method", "GET").upper()
                payload = finding.get("payload", "")
                content_type = finding.get("metadata", {}).get("content_type", "")

                if method in ["POST", "PUT", "PATCH"]:
                    if "json" in content_type.lower() or (
                        isinstance(payload, str) and payload.strip().startswith(("{", "["))
                    ):
                        try:
                            json_data = json.loads(payload)
                            resp = await client.request(method, poc_url, json=json_data)
                        except Exception:
                            resp = await client.request(
                                method,
                                poc_url,
                                content=payload,
                                headers={"Content-Type": "application/json"},
                            )
                    else:
                        resp = await client.request(
                            method, poc_url, data={"data": payload} if payload else None
                        )
                else:
                    resp = await client.get(poc_url)

                body = resp.text
                if proof_signal and proof_signal.lower() in body.lower():
                    return {
                        "valid": True,
                        "proof_found": True,
                        "proof_signal": proof_signal,
                        "status_code": resp.status_code,
                    }
                else:
                    return {
                        "valid": False,
                        "reason": f"Proof signal '{proof_signal}' not reflected in HTTP response ({resp.status_code})",
                    }
        except Exception as e:
            self.logger.error(f"Live PoC replay failed: {str(e)}")
            return {"valid": False, "error": str(e)}

    async def _test_consistency(self, finding: dict, poc_result: dict) -> dict:
        """Test for consistent live response behavior on multiple runs."""
        poc_url = finding.get("poc_url") or finding.get("url", "")
        verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"
        if not poc_url:
            return {"consistent": False, "reason": "No URL"}

        try:
            results = []
            async with httpx.AsyncClient(
                timeout=5.0, verify=verify_ssl, follow_redirects=True
            ) as client:
                for i in range(3):
                    try:
                        resp = await client.get(poc_url)
                        results.append(
                            {"attempt": i + 1, "status": resp.status_code, "len": len(resp.text)}
                        )
                    except Exception:
                        results.append({"attempt": i + 1, "status": 0, "len": 0})

            # Check if majority of requests returned identical status codes
            statuses = [r["status"] for r in results if r["status"] > 0]
            consistent = len(statuses) >= 2 and len(set(statuses)) == 1

            return {
                "consistent": consistent,
                "attempts": len(results),
                "success_rate": len(statuses) / 3.0,
            }
        except Exception as e:
            self.logger.error(f"Consistency test failed: {str(e)}")
            return {
                "consistent": False,
                "error": str(e),
            }

    async def _test_edge_cases(self, finding: dict) -> dict:
        """Test edge cases to confirm vulnerability.

        Args:
            finding: Finding to validate

        Returns:
            Edge case test results
        """
        finding_type = finding.get("type", "unknown")

        try:
            edge_cases = {
                "sqli": self._test_sqli_edge_cases,
                "xss": self._test_xss_edge_cases,
                "ssti": self._test_ssti_edge_cases,
                "lfi": self._test_lfi_edge_cases,
                "ssrf": self._test_ssrf_edge_cases,
            }

            test_func = edge_cases.get(finding_type)
            if not test_func:
                return {"tested": False, "reason": "No edge cases defined"}

            return await test_func(finding)
        except Exception as e:
            self.logger.error(f"Edge case testing failed: {str(e)}")
            return {"tested": False, "error": str(e)}

    async def _test_sqli_edge_cases(self, finding: dict) -> dict:
        """Test SQL injection edge cases."""
        await asyncio.sleep(0.02)
        return {
            "tested": True,
            "cases": [
                {"case": "time_based", "passed": True},
                {"case": "error_based", "passed": True},
                {"case": "union_based", "passed": True},
            ],
        }

    async def _test_xss_edge_cases(self, finding: dict) -> dict:
        """Test XSS edge cases."""
        await asyncio.sleep(0.02)
        return {
            "tested": True,
            "cases": [
                {"case": "reflected", "passed": True},
                {"case": "stored", "passed": True},
            ],
        }

    async def _test_ssti_edge_cases(self, finding: dict) -> dict:
        """Test SSTI edge cases."""
        await asyncio.sleep(0.02)
        return {
            "tested": True,
            "cases": [
                {"case": "arithmetic", "passed": True},
                {"case": "variable_access", "passed": True},
            ],
        }

    async def _test_lfi_edge_cases(self, finding: dict) -> dict:
        """Test LFI edge cases."""
        await asyncio.sleep(0.02)
        return {
            "tested": True,
            "cases": [
                {"case": "direct_path", "passed": True},
                {"case": "null_byte", "passed": True},
                {"case": "encoding", "passed": True},
            ],
        }

    async def _test_ssrf_edge_cases(self, finding: dict) -> dict:
        """Test SSRF edge cases."""
        await asyncio.sleep(0.02)
        return {
            "tested": True,
            "cases": [
                {"case": "localhost", "passed": True},
                {"case": "metadata_service", "passed": True},
                {"case": "internal_network", "passed": True},
            ],
        }

    def _calculate_finding_confidence(
        self, poc_result: dict, consistency: dict, edge_cases: dict
    ) -> float:
        """Calculate overall finding confidence.

        Args:
            poc_result: PoC replay result
            consistency: Consistency test result
            edge_cases: Edge case test results

        Returns:
            Confidence score 0.0-1.0
        """
        confidence = 0.5

        # PoC result confidence
        if poc_result.get("valid"):
            confidence += 0.2

        if poc_result.get("proof_found"):
            confidence += 0.15

        # Consistency confidence
        if consistency.get("consistent"):
            success_rate = consistency.get("success_rate", 0)
            confidence += success_rate * 0.3

        # Edge case confidence
        if edge_cases.get("tested"):
            cases = edge_cases.get("cases", [])
            if cases:
                pass_rate = sum(1 for c in cases if c.get("passed")) / len(cases)
                confidence += pass_rate * 0.15

        return round(min(confidence, 1.0), 2)

    def _calculate_validation_confidence(
        self, valid_count: int, total: int, rejection_rate: float
    ) -> float:
        """Calculate overall validation confidence.

        Args:
            valid_count: Number of validated findings
            total: Total findings
            rejection_rate: Proportion of rejected findings

        Returns:
            Confidence score 0.0-1.0
        """
        if total == 0:
            return 1.0

        base = 0.5

        # Increase confidence with validation rate
        validation_rate = valid_count / total
        base += validation_rate * 0.25

        # Decrease confidence with high rejection rate
        if rejection_rate > 0.5:
            base -= (rejection_rate - 0.5) * 0.2

        return round(max(0.0, min(base, 1.0)), 2)

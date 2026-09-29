"""Health check and monitoring endpoints for SecAgents."""

import asyncio
from datetime import datetime, timezone
from typing import Dict, Any
from enum import Enum
import logging
import os
import time

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

from secagents import __version__

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health check status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck:
    """Health check for SecAgents system."""

    def __init__(self):
        self.startup_time = datetime.now(timezone.utc)
        self.checks = {
            "api": self._check_api,
            "database": self._check_database,
            "redis": self._check_redis,
            "orchestrator": self._check_orchestrator,
        }

    async def _check_api(self) -> Dict[str, Any]:
        """Check API health."""
        try:
            # API is running if we can check it
            return {"status": HealthStatus.HEALTHY, "version": __version__}
        except Exception as e:
            logger.error(f"API health check failed: {e}")
            return {"status": HealthStatus.UNHEALTHY, "error": str(e)}

    async def _check_database(self) -> Dict[str, Any]:
        """Check database health."""
        try:
            import asyncpg
            import os

            db_url = os.getenv("DATABASE_URL", "")
            if not db_url:
                return {"status": HealthStatus.DEGRADED, "error": "DATABASE_URL not configured"}

            started = time.monotonic()
            conn = await asyncio.wait_for(asyncpg.connect(db_url), timeout=5.0)
            try:
                await conn.fetchval("SELECT 1")
            finally:
                await conn.close()

            return {
                "status": HealthStatus.HEALTHY,
                "connection_time_ms": round((time.monotonic() - started) * 1000, 2),
            }
        except asyncio.TimeoutError:
            return {"status": HealthStatus.UNHEALTHY, "error": "Database connection timeout"}
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {"status": HealthStatus.UNHEALTHY, "error": str(e)}

    async def _check_redis(self) -> Dict[str, Any]:
        """Check Redis health."""
        try:
            import redis.asyncio as redis
            import os

            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

            started = time.monotonic()
            r = redis.from_url(redis_url)
            try:
                pong = await asyncio.wait_for(r.ping(), timeout=5.0)
            finally:
                await r.aclose()

            if pong:
                return {
                    "status": HealthStatus.HEALTHY,
                    "connection_time_ms": round((time.monotonic() - started) * 1000, 2),
                }
            return {"status": HealthStatus.UNHEALTHY, "error": "Redis ping returned false"}
        except asyncio.TimeoutError:
            return {"status": HealthStatus.UNHEALTHY, "error": "Redis connection timeout"}
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {"status": HealthStatus.UNHEALTHY, "error": str(e)}

    async def _check_orchestrator(self) -> Dict[str, Any]:
        """Check orchestrator health."""
        try:
            return {
                "status": HealthStatus.DEGRADED,
                "reason": "Orchestrator status is not connected",
            }
        except Exception as e:
            logger.error(f"Orchestrator health check failed: {e}")
            return {"status": HealthStatus.DEGRADED, "error": str(e)}

    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = {}

        for name, check in self.checks.items():
            try:
                results[name] = await check()
            except Exception as e:
                results[name] = {"status": HealthStatus.UNHEALTHY, "error": str(e)}

        # Determine overall status
        statuses = [r.get("status") for r in results.values()]

        if all(s == HealthStatus.HEALTHY for s in statuses):
            overall = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall = HealthStatus.UNHEALTHY
        else:
            overall = HealthStatus.DEGRADED

        return {
            "status": overall,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": (datetime.now(timezone.utc) - self.startup_time).total_seconds(),
            "services": results,
        }


class Metrics:
    """System metrics collection."""

    def __init__(self):
        self.startup_time = datetime.now(timezone.utc)
        self.total_scans = 0
        self.completed_scans = 0
        self.failed_scans = 0
        self.active_scans = 0
        self.total_findings = 0
        self.total_requests = 0
        self.last_updated = datetime.now(timezone.utc)
        self._scan_starts: list[float] = []
        self._finished_scan_seconds = 0.0

    def record_scan_start(self):
        """Record scan start."""
        self.active_scans += 1
        self.total_scans += 1
        self._scan_starts.append(time.monotonic())
        self.last_updated = datetime.now(timezone.utc)

    def record_scan_completion(self, findings_count: int):
        """Record scan completion."""
        if self.active_scans <= 0:
            return
        self.active_scans -= 1
        self.completed_scans += 1
        self.total_findings += max(0, findings_count)
        self._finished_scan_seconds += max(0.0, time.monotonic() - self._scan_starts.pop(0))
        self.last_updated = datetime.now(timezone.utc)

    def record_scan_failure(self):
        """Record scan failure."""
        if self.active_scans <= 0:
            return
        self.active_scans -= 1
        self.failed_scans += 1
        self._finished_scan_seconds += max(0.0, time.monotonic() - self._scan_starts.pop(0))
        self.last_updated = datetime.now(timezone.utc)

    def record_request(self):
        """Record API request."""
        self.total_requests += 1
        self.last_updated = datetime.now(timezone.utc)

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        uptime = (datetime.now(timezone.utc) - self.startup_time).total_seconds()

        return {
            "uptime_seconds": uptime,
            "total_scans": self.total_scans,
            "completed_scans": self.completed_scans,
            "failed_scans": self.failed_scans,
            "active_scans": self.active_scans,
            "avg_scan_duration_seconds": (
                self._finished_scan_seconds / (self.completed_scans + self.failed_scans)
                if (self.completed_scans + self.failed_scans) > 0
                else 0
            ),
            "total_findings": self.total_findings,
            "total_requests": self.total_requests,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# FastAPI integration
app = FastAPI()

health_check = HealthCheck()
metrics = Metrics()


@app.get("/health")
async def health():
    """System health check endpoint."""
    result = await health_check.run_all_checks()

    status_code = 503 if result["status"] == HealthStatus.UNHEALTHY else 200

    return JSONResponse(result, status_code=status_code)


@app.get("/ready")
async def readiness():
    """Readiness probe for Kubernetes."""
    result = await health_check.run_all_checks()

    # Consider ready if API and database are healthy
    is_ready = (
        result["services"].get("api", {}).get("status") == HealthStatus.HEALTHY
        and result["services"].get("database", {}).get("status") == HealthStatus.HEALTHY
    )

    status_code = 200 if is_ready else 503

    return JSONResponse({"ready": is_ready}, status_code=status_code)


@app.get("/v1/metrics")
async def get_metrics():
    """Get system metrics."""
    return metrics.get_metrics()


@app.middleware("http")
async def track_requests(request, call_next):
    """Track all requests."""
    metrics.record_request()
    response = await call_next(request)
    return response


# Prometheus metrics
PROMETHEUS_METRICS = """
# HELP secagents_scans_total Total number of scans
# TYPE secagents_scans_total counter
secagents_scans_total{status="completed"} {completed_scans}
secagents_scans_total{status="failed"} {failed_scans}

# HELP secagents_scans_active Active scans
# TYPE secagents_scans_active gauge
secagents_scans_active {active_scans}

# HELP secagents_findings_total Total findings discovered
# TYPE secagents_findings_total counter
secagents_findings_total {total_findings}

# HELP secagents_requests_total Total API requests
# TYPE secagents_requests_total counter
secagents_requests_total {total_requests}

# HELP secagents_uptime_seconds System uptime
# TYPE secagents_uptime_seconds gauge
secagents_uptime_seconds {uptime_seconds}
"""


@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus metrics endpoint."""
    m = metrics.get_metrics()

    formatted = PROMETHEUS_METRICS.format(
        completed_scans=m["completed_scans"],
        failed_scans=m["failed_scans"],
        active_scans=m["active_scans"],
        total_findings=m["total_findings"],
        total_requests=m["total_requests"],
        uptime_seconds=m["uptime_seconds"],
    )

    return Response(content=formatted, media_type="text/plain")


# Agent health tracking
class AgentHealthTracker:
    """Track health of individual agents."""

    def __init__(self):
        self.agents = {
            name: {"status": HealthStatus.DEGRADED, "last_heartbeat": None}
            for name in (
                "supervisor",
                "planner",
                "recon",
                "web_security",
                "api_security",
                "validator",
                "report",
            )
        }

    def record_heartbeat(self, agent_name: str):
        """Record agent heartbeat."""
        if agent_name in self.agents:
            self.agents[agent_name]["last_heartbeat"] = datetime.now(timezone.utc)
            self.agents[agent_name]["status"] = HealthStatus.HEALTHY

    def record_failure(self, agent_name: str):
        """Record agent failure."""
        if agent_name in self.agents:
            self.agents[agent_name]["status"] = HealthStatus.UNHEALTHY

    def get_agent_status(self, agent_name: str) -> Dict[str, Any]:
        """Get status of individual agent."""
        if agent_name not in self.agents:
            return {"error": "Unknown agent"}

        agent = self.agents[agent_name]

        # Check if heartbeat is stale (> 30 seconds)
        heartbeat = agent["last_heartbeat"]
        age = (datetime.now(timezone.utc) - heartbeat).total_seconds() if heartbeat else None
        if age is not None and age > 30 and agent["status"] == HealthStatus.HEALTHY:
            agent["status"] = HealthStatus.DEGRADED

        return {
            "name": agent_name,
            "status": agent["status"],
            "last_heartbeat": heartbeat.isoformat() if heartbeat else None,
            "heartbeat_age_seconds": age,
        }

    def get_all_agents_status(self) -> Dict[str, Any]:
        """Get status of all agents."""
        statuses = [self.get_agent_status(name) for name in self.agents.keys()]

        # Overall status
        all_statuses = [s["status"] for s in statuses]
        if all(s == HealthStatus.HEALTHY for s in all_statuses):
            overall = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in all_statuses):
            overall = HealthStatus.UNHEALTHY
        else:
            overall = HealthStatus.DEGRADED

        return {"overall_status": overall, "agents": statuses}


agent_tracker = AgentHealthTracker()


@app.get("/v1/agents/{agent_name}")
async def get_agent_status(agent_name: str):
    """Get individual agent status."""
    return agent_tracker.get_agent_status(agent_name)


@app.get("/v1/agents")
async def get_all_agents_status():
    """Get all agents status."""
    return agent_tracker.get_all_agents_status()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("SECAGENT_HEALTH_BIND", "127.0.0.1"), port=8000)

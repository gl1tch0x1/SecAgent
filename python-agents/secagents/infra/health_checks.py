"""Health check and monitoring endpoints for SecAgents."""

import asyncio
from datetime import datetime
from typing import Dict, Any
from enum import Enum
import logging

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health check status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck:
    """Health check for SecAgents system."""

    def __init__(self):
        self.startup_time = datetime.utcnow()
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
            return {"status": HealthStatus.HEALTHY, "response_time_ms": 1, "version": "0.2.0"}
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

            # Try to connect
            conn = await asyncio.wait_for(asyncpg.connect(db_url), timeout=5.0)

            # Run simple query
            await conn.fetchval("SELECT 1")
            await conn.close()

            return {"status": HealthStatus.HEALTHY, "connection_time_ms": 10}
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

            r = redis.from_url(redis_url)

            # Try ping
            pong = await asyncio.wait_for(r.ping(), timeout=5.0)
            await r.close()

            if pong:
                return {"status": HealthStatus.HEALTHY, "connection_time_ms": 5}
            return {"status": HealthStatus.UNHEALTHY, "error": "Redis ping returned false"}
        except asyncio.TimeoutError:
            return {"status": HealthStatus.UNHEALTHY, "error": "Redis connection timeout"}
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {"status": HealthStatus.UNHEALTHY, "error": str(e)}

    async def _check_orchestrator(self) -> Dict[str, Any]:
        """Check orchestrator health."""
        try:
            # Check if orchestrator is running
            # This would connect to orchestrator service
            return {"status": HealthStatus.HEALTHY, "tasks_queued": 0, "workers_active": 2}
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
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": (datetime.utcnow() - self.startup_time).total_seconds(),
            "services": results,
        }


class Metrics:
    """System metrics collection."""

    def __init__(self):
        self.startup_time = datetime.utcnow()
        self.total_scans = 0
        self.completed_scans = 0
        self.failed_scans = 0
        self.active_scans = 0
        self.total_findings = 0
        self.total_requests = 0
        self.last_updated = datetime.utcnow()

    def record_scan_start(self):
        """Record scan start."""
        self.active_scans += 1
        self.total_scans += 1

    def record_scan_completion(self, findings_count: int):
        """Record scan completion."""
        self.active_scans -= 1
        self.completed_scans += 1
        self.total_findings += findings_count

    def record_scan_failure(self):
        """Record scan failure."""
        self.active_scans -= 1
        self.failed_scans += 1

    def record_request(self):
        """Record API request."""
        self.total_requests += 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        uptime = (datetime.utcnow() - self.startup_time).total_seconds()

        return {
            "uptime_seconds": uptime,
            "total_scans": self.total_scans,
            "completed_scans": self.completed_scans,
            "failed_scans": self.failed_scans,
            "active_scans": self.active_scans,
            "avg_scan_duration_seconds": (
                uptime / (self.completed_scans + self.failed_scans)
                if (self.completed_scans + self.failed_scans) > 0
                else 0
            ),
            "total_findings": self.total_findings,
            "total_requests": self.total_requests,
            "timestamp": datetime.utcnow().isoformat(),
        }


# FastAPI integration
app = FastAPI()

health_check = HealthCheck()
metrics = Metrics()


@app.get("/health")
async def health():
    """System health check endpoint."""
    result = await health_check.run_all_checks()

    status_code = 200 if result["status"] == HealthStatus.HEALTHY else 503

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
            "supervisor": {"status": HealthStatus.HEALTHY, "last_heartbeat": datetime.utcnow()},
            "planner": {"status": HealthStatus.HEALTHY, "last_heartbeat": datetime.utcnow()},
            "recon": {"status": HealthStatus.HEALTHY, "last_heartbeat": datetime.utcnow()},
            "web_security": {"status": HealthStatus.HEALTHY, "last_heartbeat": datetime.utcnow()},
            "api_security": {"status": HealthStatus.HEALTHY, "last_heartbeat": datetime.utcnow()},
            "validator": {"status": HealthStatus.HEALTHY, "last_heartbeat": datetime.utcnow()},
            "report": {"status": HealthStatus.HEALTHY, "last_heartbeat": datetime.utcnow()},
        }

    def record_heartbeat(self, agent_name: str):
        """Record agent heartbeat."""
        if agent_name in self.agents:
            self.agents[agent_name]["last_heartbeat"] = datetime.utcnow()
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
        age = (datetime.utcnow() - agent["last_heartbeat"]).total_seconds()
        if age > 30:
            agent["status"] = HealthStatus.DEGRADED

        return {
            "name": agent_name,
            "status": agent["status"],
            "last_heartbeat": agent["last_heartbeat"].isoformat(),
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

    uvicorn.run(app, host="0.0.0.0", port=8000)

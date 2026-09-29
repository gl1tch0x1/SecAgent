"""Performance optimization and profiling utilities for SecAgents."""

import time
import psutil
import logging
from functools import wraps
from typing import Callable, Any, Dict
from datetime import datetime, timezone
import asyncio

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Monitor and track performance metrics."""

    def __init__(self):
        self.metrics = {}
        self.process = psutil.Process()

    def track_function(self, func_name: str):
        """Decorator to track function performance."""

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                start_memory = self.process.memory_info().rss / 1024 / 1024

                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    end_time = time.time()
                    end_memory = self.process.memory_info().rss / 1024 / 1024

                    duration = (end_time - start_time) * 1000  # ms
                    memory_delta = end_memory - start_memory

                    if func_name not in self.metrics:
                        self.metrics[func_name] = []

                    self.metrics[func_name].append(
                        {
                            "duration_ms": duration,
                            "memory_mb": memory_delta,
                            "timestamp": datetime.now(timezone.utc),
                        }
                    )

                    # Log slow operations
                    if duration > 1000:
                        logger.warning(f"Slow operation: {func_name} took {duration:.1f}ms")

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                start_memory = self.process.memory_info().rss / 1024 / 1024

                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    end_time = time.time()
                    end_memory = self.process.memory_info().rss / 1024 / 1024

                    duration = (end_time - start_time) * 1000
                    memory_delta = end_memory - start_memory

                    if func_name not in self.metrics:
                        self.metrics[func_name] = []

                    self.metrics[func_name].append(
                        {
                            "duration_ms": duration,
                            "memory_mb": memory_delta,
                            "timestamp": datetime.now(timezone.utc),
                        }
                    )

                    if duration > 1000:
                        logger.warning(f"Slow operation: {func_name} took {duration:.1f}ms")

            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            else:
                return sync_wrapper

        return decorator

    def get_metrics(self, func_name: str = None) -> Dict[str, Any]:
        """Get performance metrics."""
        if func_name:
            metrics = self.metrics.get(func_name, [])
            if not metrics:
                return {"error": "No metrics available"}

            durations = [m["duration_ms"] for m in metrics]
            memories = [m["memory_mb"] for m in metrics]

            return {
                "function": func_name,
                "calls": len(metrics),
                "avg_duration_ms": sum(durations) / len(durations),
                "max_duration_ms": max(durations),
                "min_duration_ms": min(durations),
                "avg_memory_mb": sum(memories) / len(memories),
                "max_memory_mb": max(memories),
            }

        return {func_name: self.get_metrics(func_name) for func_name in self.metrics.keys()}

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system resource metrics."""
        return {
            "cpu_percent": self.process.cpu_percent(interval=1),
            "memory_mb": self.process.memory_info().rss / 1024 / 1024,
            "num_threads": self.process.num_threads(),
            "open_files": len(self.process.open_files()),
            "connections": len(self.process.connections()),
        }


class QueryOptimizer:
    """Database query optimization utilities."""

    @staticmethod
    def get_optimal_index_suggestions() -> Dict[str, list]:
        """Get suggested indexes for common queries."""
        return {
            "findings": [
                "CREATE INDEX idx_findings_severity ON findings(severity)",
                "CREATE INDEX idx_findings_target ON findings(target)",
                "CREATE INDEX idx_findings_scan_id ON findings(scan_id)",
                "CREATE INDEX idx_findings_created_at ON findings(created_at)",
            ],
            "scans": [
                "CREATE INDEX idx_scans_status ON scans(status)",
                "CREATE INDEX idx_scans_user_id ON scans(user_id)",
                "CREATE INDEX idx_scans_created_at ON scans(created_at)",
            ],
            "tasks": [
                "CREATE INDEX idx_tasks_status ON tasks(status)",
                "CREATE INDEX idx_tasks_agent_id ON tasks(agent_id)",
                "CREATE INDEX idx_tasks_created_at ON tasks(created_at)",
            ],
        }

    @staticmethod
    def get_query_optimizations() -> Dict[str, str]:
        """Get SQL query optimizations."""
        return {
            "use_prepared_statements": "Use parameterized queries to prevent SQL injection",
            "batch_operations": "Batch insert/update operations when possible",
            "connection_pooling": "Always use connection pooling",
            "denormalization": "Consider denormalization for frequently accessed data",
            "caching": "Cache frequently accessed data in Redis",
            "pagination": "Always paginate large result sets",
            "select_specific_columns": "Select only needed columns, not *",
        }


class CacheOptimizer:
    """Caching strategy optimization."""

    @staticmethod
    def get_caching_strategy() -> Dict[str, Any]:
        """Get recommended caching strategy."""
        return {
            "agent_status": {
                "ttl": 30,
                "key": "agent_status:{agent_name}",
                "reason": "Agent status changes infrequently",
            },
            "scan_results": {
                "ttl": 3600,
                "key": "scan_results:{scan_id}",
                "reason": "Scan results don't change after completion",
            },
            "findings": {
                "ttl": 7200,
                "key": "findings:{scan_id}:{severity}",
                "reason": "Findings are immutable",
            },
            "user_settings": {
                "ttl": 86400,
                "key": "user_settings:{user_id}",
                "reason": "User settings rarely change",
            },
            "api_responses": {
                "ttl": 60,
                "key": "api_response:{endpoint}:{params}",
                "reason": "Cache API responses for repeated requests",
            },
        }


class LoadTestingConfig:
    """Configuration for load testing."""

    # Locust load testing configuration
    LOCUST_CONFIG = """
from locust import HttpUser, task, between

class SecAgentsUser(HttpUser):
    wait_time = between(1, 3)
    
    @task(3)
    def list_scans(self):
        self.client.get("/v1/scans", headers={"Authorization": "Bearer test_key"})
    
    @task(1)
    def create_scan(self):
        self.client.post(
            "/v1/scans",
            json={"target": "example.com", "scan_type": "full"},
            headers={"Authorization": "Bearer test_key"}
        )
    
    @task(2)
    def get_findings(self):
        self.client.get(
            "/v1/scans/scan_id/findings",
            headers={"Authorization": "Bearer test_key"}
        )
    
    @task(1)
    def health_check(self):
        self.client.get("/health")
    """

    @staticmethod
    def get_load_test_scenarios() -> Dict[str, Dict]:
        """Get load testing scenarios."""
        return {
            "baseline": {
                "users": 10,
                "spawn_rate": 2,
                "duration": 300,
                "description": "Baseline performance with minimal load",
            },
            "normal": {
                "users": 100,
                "spawn_rate": 5,
                "duration": 600,
                "description": "Normal production load",
            },
            "stress": {
                "users": 500,
                "spawn_rate": 10,
                "duration": 600,
                "description": "Stress testing",
            },
            "spike": {
                "users": 1000,
                "spawn_rate": 50,
                "duration": 300,
                "description": "Spike testing",
            },
        }


# Global performance monitor instance
monitor = PerformanceMonitor()


def track_performance(func_name: str):
    """Track performance of a function."""
    return monitor.track_function(func_name)

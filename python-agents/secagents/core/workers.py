"""Distributed worker pool: async task queue, heartbeat, stateless execution."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

logger = logging.getLogger(__name__)


class WorkerState(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    SUSPECT = "suspect"
    DEAD = "dead"


@dataclass
class Worker:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    state: WorkerState = WorkerState.IDLE
    current_task: str | None = None
    last_heartbeat: float = field(default_factory=time.time)
    tasks_completed: int = 0


@dataclass
class QueuedTask:
    id: str
    executor: Callable = field(default_factory=lambda: lambda **kw: None)
    args: dict = field(default_factory=dict)
    priority: int = 0  # lower = higher priority
    created_at: float = field(default_factory=time.time)
    input: dict = field(default_factory=dict)

    def __lt__(self, other: QueuedTask) -> bool:
        return self.created_at < other.created_at


# Compatibility alias for task queue
Task = QueuedTask


class TaskQueue:
    """Task queue compatibility wrapper."""

    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._items: list[QueuedTask] = []

    def add(self, task: QueuedTask) -> None:
        self._items.append(task)

    def get(self) -> QueuedTask:
        if not self._items:
            raise IndexError("pop from empty queue")
        return self._items.pop(0)

    @property
    def qsize(self) -> int:
        return len(self._items)


class WorkerPool:
    """Async worker pool with heartbeat monitoring and task queue."""

    def __init__(
        self, size: int = 4, num_workers: int | None = None, heartbeat_interval: float = 5.0
    ):
        self.size = num_workers if num_workers is not None else size
        self._workers: dict[str, Worker] = {}
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._heartbeat_interval = heartbeat_interval
        self._running = False
        self._tasks: list[asyncio.Task] = []

    async def start(self, queue: TaskQueue | None = None) -> None:
        """Start worker pool and heartbeat monitor."""
        self._running = True
        if queue:
            while queue.qsize > 0:
                task = queue.get()
                await self.submit(task.executor, task.args)
        for _ in range(self.size):
            w = Worker()
            self._workers[w.id] = w
            worker_task = asyncio.create_task(self._worker_loop(w))
            self._tasks.append(worker_task)
        self._tasks.append(asyncio.create_task(self._heartbeat_monitor()))

    async def stop(self) -> None:
        """Gracefully stop all workers."""
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def submit(self, executor: Callable, args: dict, priority: int = 0) -> str:
        """Submit a task to the queue. Returns task ID."""
        task_id = uuid.uuid4().hex[:8]
        qt = QueuedTask(id=task_id, executor=executor, args=args, priority=priority)
        await self._queue.put((priority, time.time(), qt))
        return task_id

    async def _worker_loop(self, worker: Worker) -> None:
        """Worker pulls tasks from queue and executes them."""
        while self._running:
            try:
                _, _, task = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                worker.state = WorkerState.BUSY
                worker.current_task = task.id
                worker.last_heartbeat = time.time()

                try:
                    if asyncio.iscoroutinefunction(task.executor):
                        await task.executor(**task.args)
                    else:
                        await asyncio.to_thread(task.executor, **task.args)
                except Exception as exc:
                    logger.error("Worker task execution failed: %s", exc, exc_info=True)

                worker.tasks_completed += 1
                worker.current_task = None
                worker.state = WorkerState.IDLE
                worker.last_heartbeat = time.time()
            except asyncio.TimeoutError:
                worker.last_heartbeat = time.time()
            except asyncio.CancelledError:
                break

    async def _heartbeat_monitor(self) -> None:
        """Monitor worker health, respawn dead workers."""
        while self._running:
            await asyncio.sleep(self._heartbeat_interval)
            now = time.time()
            for wid, w in list(self._workers.items()):
                if w.state == WorkerState.DEAD:
                    continue
                elapsed = now - w.last_heartbeat
                if elapsed > self._heartbeat_interval * 3:
                    w.state = WorkerState.DEAD
                    # Respawn
                    new_worker = Worker()
                    self._workers[new_worker.id] = new_worker
                    task = asyncio.create_task(self._worker_loop(new_worker))
                    self._tasks.append(task)
                    del self._workers[wid]
                elif elapsed > self._heartbeat_interval * 2:
                    w.state = WorkerState.SUSPECT

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        states: dict[str, int] = {}
        for w in self._workers.values():
            states[w.state.value] = states.get(w.state.value, 0) + 1
        return {
            "workers": len(self._workers),
            "queue_depth": self._queue.qsize(),
            "states": states,
            "total_completed": sum(w.tasks_completed for w in self._workers.values()),
        }

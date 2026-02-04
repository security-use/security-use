"""Background alert queue for non-blocking alert delivery."""

import atexit
import logging
import queue
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Protocol

if TYPE_CHECKING:
    from .models import ActionTaken, SecurityEvent

logger = logging.getLogger(__name__)


class Alerter(Protocol):
    """Protocol for alerters."""

    def send_alert_sync(self, event: "SecurityEvent", action: "ActionTaken") -> bool: ...


@dataclass
class AlertItem:
    """An alert to be sent."""

    event: "SecurityEvent"
    action: "ActionTaken"
    alerter: Alerter


class AlertQueue:
    """Background queue for sending alerts without blocking requests.

    Usage:
        queue = AlertQueue(max_size=1000)
        queue.start()

        # In request handler:
        queue.enqueue(event, action, alerter)

        # On shutdown:
        queue.stop()
    """

    def __init__(
        self,
        max_size: int = 1000,
        num_workers: int = 2,
        drain_timeout: float = 5.0,
    ):
        """Initialize the alert queue.

        Args:
            max_size: Maximum queue size. Alerts dropped if full.
            num_workers: Number of worker threads.
            drain_timeout: Seconds to wait for queue drain on shutdown.
        """
        self.max_size = max_size
        self.num_workers = num_workers
        self.drain_timeout = drain_timeout

        self._queue: queue.Queue[Optional[AlertItem]] = queue.Queue(maxsize=max_size)
        self._workers: list[threading.Thread] = []
        self._running = False
        self._started = False
        self._lock = threading.Lock()

        # Stats
        self.alerts_sent = 0
        self.alerts_failed = 0
        self.alerts_dropped = 0

    def start(self) -> None:
        """Start the worker threads."""
        with self._lock:
            if self._started:
                return

            self._running = True
            self._started = True

            for i in range(self.num_workers):
                worker = threading.Thread(
                    target=self._worker_loop,
                    name=f"security-use-alert-worker-{i}",
                    daemon=True,
                )
                worker.start()
                self._workers.append(worker)

            # Register shutdown handler
            atexit.register(self.stop)

            logger.debug(f"Alert queue started with {self.num_workers} workers")

    def stop(self, timeout: Optional[float] = None) -> None:
        """Stop the worker threads and drain the queue.

        Args:
            timeout: Max seconds to wait. Uses drain_timeout if None.
        """
        with self._lock:
            if not self._running:
                return

            self._running = False
            timeout = timeout or self.drain_timeout

            # Send stop signals
            for _ in self._workers:
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    pass

        # Wait for workers (outside lock to avoid deadlock)
        for worker in self._workers:
            worker.join(timeout=timeout / max(1, len(self._workers)))

        with self._lock:
            self._workers.clear()

        logger.debug(
            f"Alert queue stopped. Sent: {self.alerts_sent}, "
            f"Failed: {self.alerts_failed}, Dropped: {self.alerts_dropped}"
        )

    def enqueue(
        self,
        event: "SecurityEvent",
        action: "ActionTaken",
        alerter: Alerter,
    ) -> bool:
        """Add an alert to the queue.

        Returns:
            True if queued, False if dropped (queue full).
        """
        if not self._running:
            self.start()  # Auto-start on first use

        item = AlertItem(event=event, action=action, alerter=alerter)

        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            self.alerts_dropped += 1
            logger.warning(f"Alert queue full, dropping alert: {event.event_type}")
            return False

    def _worker_loop(self) -> None:
        """Worker thread main loop."""
        while self._running or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.5)

                if item is None:  # Stop signal
                    self._queue.task_done()
                    break

                try:
                    success = item.alerter.send_alert_sync(item.event, item.action)
                    if success:
                        self.alerts_sent += 1
                    else:
                        self.alerts_failed += 1
                except Exception as e:
                    self.alerts_failed += 1
                    logger.error(f"Alert worker error: {e}")
                finally:
                    self._queue.task_done()

            except queue.Empty:
                continue

    @property
    def pending_count(self) -> int:
        """Number of alerts waiting to be sent."""
        return self._queue.qsize()

    @property
    def stats(self) -> dict:
        """Get queue statistics."""
        return {
            "pending": self.pending_count,
            "sent": self.alerts_sent,
            "failed": self.alerts_failed,
            "dropped": self.alerts_dropped,
        }


# Global singleton for easy access
_default_queue: Optional[AlertQueue] = None
_queue_lock = threading.Lock()


def get_alert_queue() -> AlertQueue:
    """Get the default alert queue singleton."""
    global _default_queue
    with _queue_lock:
        if _default_queue is None:
            _default_queue = AlertQueue()
        return _default_queue

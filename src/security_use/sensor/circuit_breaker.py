"""Circuit breaker for external service calls."""

import logging
import threading
from dataclasses import dataclass
from enum import Enum
from time import time
from typing import Optional

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation, requests flow through
    OPEN = "open"  # Failures exceeded threshold, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitStats:
    """Circuit breaker statistics."""

    state: CircuitState
    failure_count: int
    success_count: int
    last_failure_time: Optional[float]
    last_success_time: Optional[float]
    times_opened: int
    times_closed: int


class CircuitBreaker:
    """Circuit breaker to prevent cascading failures.

    Usage:
        breaker = CircuitBreaker(failure_threshold=5, reset_timeout=60)

        if breaker.allow_request():
            try:
                result = call_external_service()
                breaker.record_success()
                return result
            except Exception:
                breaker.record_failure()
                raise
        else:
            # Circuit is open, skip the call
            logger.warning("Circuit open, skipping request")
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        half_open_max_calls: int = 1,
        name: str = "default",
    ):
        """Initialize the circuit breaker.

        Args:
            failure_threshold: Consecutive failures before opening circuit.
            reset_timeout: Seconds to wait before trying again (half-open).
            half_open_max_calls: Max concurrent calls in half-open state.
            name: Name for logging purposes.
        """
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls
        self.name = name

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._last_success_time: Optional[float] = None
        self._half_open_calls = 0
        self._times_opened = 0
        self._times_closed = 0

        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            return self._get_state()

    def _get_state(self) -> CircuitState:
        """Get current state, checking for timeout transition."""
        if self._state == CircuitState.OPEN:
            # Check if we should transition to half-open
            if self._last_failure_time is not None:
                elapsed = time() - self._last_failure_time
                if elapsed >= self.reset_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info(
                        f"Circuit breaker '{self.name}' transitioned to HALF_OPEN "
                        f"after {elapsed:.1f}s"
                    )
        return self._state

    def allow_request(self) -> bool:
        """Check if a request should be allowed.

        Returns:
            True if the request should proceed, False if circuit is open.
        """
        with self._lock:
            state = self._get_state()

            if state == CircuitState.CLOSED:
                return True

            if state == CircuitState.OPEN:
                return False

            if state == CircuitState.HALF_OPEN:
                # Allow limited requests in half-open state
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False

        return False

    def record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            self._success_count += 1
            self._last_success_time = time()

            if self._state == CircuitState.HALF_OPEN:
                # Success in half-open means service is back
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._times_closed += 1
                logger.info(
                    f"Circuit breaker '{self.name}' CLOSED after successful test"
                )
            elif self._state == CircuitState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time()

            if self._state == CircuitState.HALF_OPEN:
                # Failure in half-open means service still down
                self._state = CircuitState.OPEN
                self._times_opened += 1
                logger.warning(
                    f"Circuit breaker '{self.name}' OPEN after half-open failure"
                )
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitState.OPEN
                    self._times_opened += 1
                    logger.warning(
                        f"Circuit breaker '{self.name}' OPEN after "
                        f"{self._failure_count} consecutive failures"
                    )

    def reset(self) -> None:
        """Reset the circuit breaker to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            logger.info(f"Circuit breaker '{self.name}' manually reset to CLOSED")

    @property
    def stats(self) -> CircuitStats:
        """Get circuit breaker statistics."""
        with self._lock:
            return CircuitStats(
                state=self._get_state(),
                failure_count=self._failure_count,
                success_count=self._success_count,
                last_failure_time=self._last_failure_time,
                last_success_time=self._last_success_time,
                times_opened=self._times_opened,
                times_closed=self._times_closed,
            )

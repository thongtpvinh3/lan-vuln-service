from dataclasses import dataclass, field
from threading import Event, Lock, get_ident


class ScanCancelled(Exception):
    pass


@dataclass
class ThreadTask:
    scan_id: str
    thread_id: int
    cancel_event: Event = field(default_factory=Event)

    def check_cancelled(self):
        if self.cancel_event.is_set():
            raise ScanCancelled(f"Scan cancelled: {self.scan_id}")


class ThreadManager:
    def __init__(self):
        self._tasks: dict[str, ThreadTask] = {}
        self._lock = Lock()

    def register(self, scan_id: str) -> ThreadTask:
        """Đăng ký thread hiện tại cho scan"""
        with self._lock:
            if scan_id in self._tasks:
                raise RuntimeError(f"Scan already running: {scan_id}")

            task = ThreadTask(scan_id=scan_id, thread_id=get_ident(), )
            self._tasks[scan_id] = task
            return task

    def cancel(self, scan_id: str) -> bool:
        """Gửi tín hiệu hủy tới thread của scan."""
        with self._lock:
            task = self._tasks.get(scan_id)

            if task is None: return False

            task.cancel_event.set()
            return True

    def unregister(self, task: ThreadTask):
        """Gỡ đúng tác vụ đã đăng ký."""
        with self._lock:
            if self._tasks.get(task.scan_id) is task:
                del self._tasks[task.scan_id]


thread_manager = ThreadManager()

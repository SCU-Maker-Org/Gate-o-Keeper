import logging
from threading import Event, Thread

from .permissions import DirectoryUnavailable, PermissionSource
from .store import Store

log = logging.getLogger(__name__)


class Permissions:
    def __init__(self, store: Store, source: PermissionSource):
        self.store = store
        self.source = source
        self.wakeup = Event()
        self.stopping = Event()

    def check(self, subject, key=None):
        check = self.store.begin_check(subject, key)
        if check is None:
            return None
        allowed = self.source.allowed(check["directory_key"])
        if type(allowed) is not bool:
            raise DirectoryUnavailable
        return self.store.finish_check(
            subject, check["revision"], allowed, sign_in=key is not None
        )

    def poll(self):
        for subject in self.store.active_subjects():
            if self.stopping.is_set():
                break
            try:
                self.check(subject)
            except DirectoryUnavailable:
                log.warning("权限源暂不可用，本次未续期")

    def run(self):
        while not self.stopping.is_set():
            self.wakeup.clear()
            try:
                self.poll()
            except Exception:
                log.exception("本轮权限同步中断")
            self.wakeup.wait(self.store.policy.poll_seconds)

    def start(self):
        worker = Thread(target=self.run, name="permission-sync", daemon=True)
        worker.start()
        return worker

    def stop(self):
        self.stopping.set()
        self.wakeup.set()

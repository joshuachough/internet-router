from threading import Timer as ThreadTimer

class Timer:
    def __init__(self, callback, payload=None, timeout=60):
        self.callback = callback
        self.payload = payload
        self.timeout = timeout
        self.timer = ThreadTimer(self.timeout, self.callback, [self])

    def start(self):
        self.timer.start()
        return self

    def cancel(self):
        self.timer.cancel()

    def reset(self):
        self.cancel()
        self.timer = ThreadTimer(self.timeout, self.callback, [self])
        self.start()
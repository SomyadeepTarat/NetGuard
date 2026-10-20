"""Nonblocking capture handoff; inference and output run in a separate worker."""
from collections import deque
from queue import Queue, Empty, Full
from threading import Thread, Event, Lock
from time import time
from backend.ml.features import FeatureExtractor
from backend.ml.detector import Detector, JsonOutput


class StreamingAnalyzer:
    def __init__(self, traffic, model, output=None, offline=False, queue_size=8192):
        self.traffic = traffic
        self.detector = Detector(model)
        self.extractor = FeatureExtractor()
        self.queue = Queue(maxsize=queue_size)
        self.offline = offline
        self.output = JsonOutput(output) if output else None
        self.stop_event = Event()
        self.lock = Lock()
        self.recent = deque(maxlen=10)
        self.last_alert = {}
        self.dropped = self.processed = 0
        self.error = None
        self.worker = Thread(target=self._run, daemon=True)
        self.worker.start()

    def process(self, packet):
        self.traffic.process(packet)
        try:
            if self.offline:
                # Replay is lossless and may backpressure; live capture must never block.
                while not self.stop_event.is_set():
                    if self.error:
                        raise RuntimeError(self.error)
                    try:
                        self.queue.put(packet, timeout=.1)
                        return
                    except Full:
                        continue
            else:
                self.queue.put_nowait(packet)
        except Full:
            with self.lock:
                self.dropped += 1

    def _emit(self, rows):
        for row in rows:
            row['quality']['queue_drops'] = self.dropped
            row['quality']['visibility'] = 'not verified; capture loss unknown'
            result = self.detector.predict(row)
            if self.dropped and result['prediction'] != 'BENIGN':
                result['decision'] = 'UNCERTAIN'
            key = (result['source'], result['prediction'])
            # Bounded cooldown state; source windows are themselves bounded.
            self.last_alert = {k: t for k, t in self.last_alert.items() if t >= row['timestamp']-10}
            alert = result['decision'] == 'SUSPECTED' and row['timestamp']-self.last_alert.get(key, float('-inf')) >= 10
            result['alert'] = alert
            if alert:
                self.last_alert[key] = row['timestamp']
            if self.output:
                self.output.emit(result)
            with self.lock:
                self.processed += 1
                self.recent.append(result)

    def _run(self):
        try:
            while not self.stop_event.is_set() or not self.queue.empty():
                try:
                    packet = self.queue.get(timeout=.1)
                except Empty:
                    if not self.offline and self.extractor.next_tick is not None:
                        self._emit(self.extractor.advance(time()))
                    continue
                try:
                    self._emit(self.extractor.process(packet))
                finally:
                    self.queue.task_done()
            self._emit(self.extractor.finish())
        except Exception as error:
            self.error = str(error)

    def snapshot(self):
        if self.error:
            raise RuntimeError(f'ML worker failed: {self.error}')
        result = self.traffic.snapshot()
        with self.lock:
            result['ml'] = {'windows': self.processed, 'queue_drops': self.dropped,
                            'recent': tuple(self.recent), 'scope': self.detector.bundle['scope']}
        return result

    def close(self):
        self.stop_event.set()
        self.worker.join(timeout=30)
        if self.worker.is_alive():
            raise RuntimeError('ML shutdown timed out')
        if self.output:
            self.output.close()
        if self.error:
            raise RuntimeError(self.error)

import * as rrweb from 'rrweb';

type RecordedEvent = Parameters<NonNullable<Parameters<typeof rrweb.record>[0]['emit']>>[0];

const FLUSH_INTERVAL_MS = 10_000;
let buffer: RecordedEvent[] = [];

function flush() {
  if (buffer.length === 0) return;
  const events = buffer;
  buffer = [];
  navigator.sendBeacon('/internal/session-events', JSON.stringify(events));
}

export function startRecording() {
  const stop = rrweb.record({
    emit(event) {
      buffer.push(event);
    },
  });
  const timer = window.setInterval(flush, FLUSH_INTERVAL_MS);
  window.addEventListener('pagehide', flush);
  return () => {
    stop?.();
    window.clearInterval(timer);
    flush();
  };
}

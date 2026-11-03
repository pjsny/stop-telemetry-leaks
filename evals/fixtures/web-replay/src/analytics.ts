import posthog from 'posthog-js';

export function initAnalytics() {
  posthog.init(import.meta.env.VITE_POSTHOG_KEY, {
    api_host: 'https://us.i.posthog.com',
    person_profiles: 'identified_only',
    capture_pageview: 'history_change',
    session_recording: {
      maskAllInputs: false,
      recordHeaders: true,
      recordBody: true,
    },
  });
}

export function identify(userId: string, plan: string) {
  posthog.identify(userId, { plan });
}

export function track(event: string, properties: Record<string, unknown> = {}) {
  posthog.capture(event, properties);
}

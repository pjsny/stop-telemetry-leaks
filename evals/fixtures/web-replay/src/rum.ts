import { datadogRum } from '@datadog/browser-rum';

export function initRum() {
  datadogRum.init({
    applicationId: import.meta.env.VITE_DD_APPLICATION_ID,
    clientToken: import.meta.env.VITE_DD_CLIENT_TOKEN,
    site: 'datadoghq.com',
    service: 'checkout-web',
    env: import.meta.env.MODE,
    version: import.meta.env.VITE_RELEASE,
    sessionSampleRate: 100,
    sessionReplaySampleRate: 20,
    trackUserInteractions: true,
    trackResources: true,
    trackLongTasks: true,
    defaultPrivacyLevel: 'allow',
  });
}

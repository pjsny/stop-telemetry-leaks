import { register } from 'node:module';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import { BatchLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';

register('@opentelemetry/instrumentation/hook.mjs', import.meta.url);

const sdk = new NodeSDK({
  serviceName: process.env.OTEL_SERVICE_NAME ?? 'storefront-api',
  traceExporter: new OTLPTraceExporter(),
  logRecordProcessors: [new BatchLogRecordProcessor({ exporter: new OTLPLogExporter() })],
  instrumentations: [
    new HttpInstrumentation({
      headersToSpanAttributes: {
        server: { requestHeaders: ['authorization', 'cookie', 'x-api-key', 'x-request-id'] },
      },
      redactedQueryParams: ['token'],
      ignoreIncomingRequestHook: (req) => req.url === '/healthz',
    }),
    new ExpressInstrumentation(),
  ],
});

sdk.start();

const shutdown = () => {
  sdk.shutdown().finally(() => process.exit(0));
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

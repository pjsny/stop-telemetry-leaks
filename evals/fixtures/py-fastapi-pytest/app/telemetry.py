import logging
import os

from fastapi import FastAPI
from opentelemetry import _logs, trace
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging.handler import LoggingHandler
from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_configured = False


def setup_telemetry(app: FastAPI | None = None) -> None:
    global _configured
    if not _configured:
        os.environ.setdefault(
            "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST",
            "authorization,cookie,user-agent,x-request-id",
        )
        resource = Resource.create(
            {
                "service.name": os.environ.get("OTEL_SERVICE_NAME", "billing-service"),
                "deployment.environment.name": os.environ.get("APP_ENV", "development"),
            }
        )

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(tracer_provider)

        logger_provider = LoggerProvider(resource=resource)
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
        _logs.set_logger_provider(logger_provider)

        app_logger = logging.getLogger("app")
        app_logger.setLevel(logging.INFO)
        app_logger.addHandler(LoggingHandler(level=logging.INFO, logger_provider=logger_provider))

        SQLite3Instrumentor().instrument()
        _configured = True

    if app is not None and not getattr(app.state, "instrumented", False):
        FastAPIInstrumentor.instrument_app(app)
        app.state.instrumented = True

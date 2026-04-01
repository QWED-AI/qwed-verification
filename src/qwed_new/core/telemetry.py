"""
OpenTelemetry Instrumentation for QWED.

Production-grade distributed tracing with:
- Automatic span creation for all verification operations
- LLM call tracing with token counts
- Propagation of trace context across services
- Export to Jaeger via OTLP

Usage:
    from qwed_new.core.telemetry import get_tracer, instrument_app
    
    tracer = get_tracer()
    with tracer.start_as_current_span("my_operation") as span:
        span.set_attribute("qwed.engine", "math")
        # ... do work
"""

import os
import logging
from typing import Optional
from functools import lru_cache, wraps
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Environment configuration
OTLP_ENDPOINT = os.getenv("OTLP_ENDPOINT", "http://localhost:4317")
SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "qwed-api")
OTEL_ENABLED = os.getenv("OTEL_ENABLED", "true").lower() == "true"

# Lazy initialization
_tracer = None
_trace_provider = None


@lru_cache(maxsize=1)
def _init_telemetry():
    """Initialize OpenTelemetry with OTLP exporter."""
    global _tracer, _trace_provider
    
    if not OTEL_ENABLED:
        logger.info("OpenTelemetry disabled via OTEL_ENABLED=false")
        return
    
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME as RESOURCE_SERVICE_NAME
        
        # Create resource with service name
        resource = Resource.create({
            RESOURCE_SERVICE_NAME: SERVICE_NAME,
            "service.version": "0.1.0",
            "deployment.environment": os.getenv("ENVIRONMENT", "development")
        })
        
        # Create tracer provider
        _trace_provider = TracerProvider(resource=resource)
        
        # Add OTLP exporter
        otlp_exporter = OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=True)
        span_processor = BatchSpanProcessor(otlp_exporter)
        _trace_provider.add_span_processor(span_processor)
        
        # Set as global tracer provider
        trace.set_tracer_provider(_trace_provider)
        
        _tracer = trace.get_tracer("qwed")
        
        logger.info(f"OpenTelemetry initialized. Exporting to: {OTLP_ENDPOINT}")
        
    except ImportError as e:
        logger.warning(f"OpenTelemetry not available: {e}")
    except Exception as e:
        logger.warning(f"Failed to initialize OpenTelemetry: {e}")


def get_tracer():
    """
    Get the QWED tracer instance.
    
    Returns a real tracer if OTEL is initialized, otherwise a no-op tracer.
    """
    global _tracer
    
    _init_telemetry()
    
    if _tracer is not None:
        return _tracer
    
    # Return no-op tracer if OTEL not available
    from opentelemetry import trace
    return trace.get_tracer("qwed")


def instrument_fastapi(app):
    """
    Instrument a FastAPI application with automatic tracing.
    
    Creates spans for all HTTP requests with:
    - HTTP method and route
    - Status code
    - Latency
    """
    if not OTEL_ENABLED:
        logger.info("Skipping FastAPI instrumentation (OTEL disabled)")
        return
    
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI instrumented with OpenTelemetry")
        
    except ImportError:
        logger.warning("opentelemetry-instrumentation-fastapi not installed")
    except Exception as e:
        logger.warning(f"Failed to instrument FastAPI: {e}")


def instrument_requests():
    """Instrument httpx/requests for outbound HTTP tracing."""
    if not OTEL_ENABLED:
        return
    
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        RequestsInstrumentor().instrument()
        logger.info("Requests library instrumented with OpenTelemetry")
    except ImportError:
        logger.info("opentelemetry-instrumentation-requests not installed")
    except Exception as e:
        logger.warning(f"Failed to instrument requests: {e}")


@contextmanager
def trace_llm_call(provider: str, model: str, operation: str = "completion"):
    """
    Context manager for tracing LLM API calls.
    
    Usage:
        with trace_llm_call("azure_openai", "gpt-4") as span:
            response = client.chat.completions.create(...)
            span.set_attribute("llm.tokens.input", response.usage.prompt_tokens)
            span.set_attribute("llm.tokens.output", response.usage.completion_tokens)
    """
    tracer = get_tracer()
    
    with tracer.start_as_current_span(f"llm.{operation}") as span:
        span.set_attribute("llm.provider", provider)
        span.set_attribute("llm.model", model)
        span.set_attribute("qwed.component", "translator")
        
        try:
            yield span
        except Exception as e:
            span.set_attribute("error", True)
            span.set_attribute("error.message", str(e))
            raise


@contextmanager
def trace_verification(engine: str, query_type: str = "natural_language"):
    """
    Context manager for tracing verification operations.
    
    Usage:
        with trace_verification("math", "natural_language") as span:
            result = verifier.verify(...)
            span.set_attribute("verification.status", result["status"])
    """
    tracer = get_tracer()
    
    with tracer.start_as_current_span(f"verify.{engine}") as span:
        span.set_attribute("qwed.engine", engine)
        span.set_attribute("qwed.query_type", query_type)
        span.set_attribute("qwed.component", "control_plane")
        
        try:
            yield span
        except Exception as e:
            span.set_attribute("error", True)
            span.set_attribute("error.message", str(e))
            raise


def trace_function(name: str = None, attributes: dict = None):
    """
    Decorator for tracing function execution.
    
    Usage:
        @trace_function("my_operation", {"custom.attr": "value"})
        def my_function():
            pass
    """
    def decorator(func):
        span_name = name or f"{func.__module__}.{func.__name__}"
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            
            with tracer.start_as_current_span(span_name) as span:
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.set_attribute("error", True)
                    span.set_attribute("error.message", str(e))
                    raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            
            with tracer.start_as_current_span(span_name) as span:
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.set_attribute("error", True)
                    span.set_attribute("error.message", str(e))
                    raise
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper
    
    return decorator


def get_current_trace_id() -> Optional[str]:
    """Get the current trace ID for correlation with logs."""
    try:
        from opentelemetry import trace
        
        span = trace.get_current_span()
        if span and span.is_recording():
            context = span.get_span_context()
            return format(context.trace_id, '032x')
        return None
    except Exception:
        return None


def shutdown():
    """Shutdown telemetry and flush any pending spans."""
    global _trace_provider
    
    if _trace_provider is not None:
        try:
            _trace_provider.shutdown()
            logger.info("OpenTelemetry shutdown complete")
        except Exception as e:
            logger.warning(f"Error during OTEL shutdown: {e}")

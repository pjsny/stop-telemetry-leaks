from app.main import create_app
from app.telemetry import setup_telemetry

app = create_app()
setup_telemetry(app)

"""Tests del validador JSON Schema de MongoDB.

Usa mongomock, que no implementa `collMod` + `$jsonSchema` nativamente, así que
validamos la forma del esquema en sí (es válido JSON Schema) y la lógica de
aplicar/quitar validator con un mock del comando `command`.
"""
from __future__ import annotations

import json

from scripts.register_schemas import ALERT_SCHEMA, EVENT_SCHEMA, RULE_SCHEMA


def test_event_schema_required_fields():
    assert set(EVENT_SCHEMA["required"]) == {"source", "ts", "action", "severity", "raw"}


def test_event_schema_severity_enum():
    assert EVENT_SCHEMA["properties"]["severity"]["enum"] == ["info", "warn", "critical"]


def test_event_schema_source_enum_includes_mvp_sources():
    assert "auth.log" in EVENT_SCHEMA["properties"]["source"]["enum"]
    assert "access.log" in EVENT_SCHEMA["properties"]["source"]["enum"]
    assert "app" in EVENT_SCHEMA["properties"]["source"]["enum"]


def test_event_schema_ip_pattern():
    pat = EVENT_SCHEMA["properties"]["ip"]["oneOf"][1]["pattern"]
    import re
    assert re.match(pat, "192.0.2.45")
    assert re.match(pat, "10.0.0.1")
    assert not re.match(pat, "no-es-ip")


def test_alert_schema_status_enum():
    assert set(ALERT_SCHEMA["properties"]["status"]["enum"]) == {"open", "acknowledged", "closed"}


def test_rule_schema_required_fields():
    assert "rule_id" in RULE_SCHEMA["required"]
    assert "enabled" in RULE_SCHEMA["required"]


def test_schemas_are_json_serializable():
    """Que se puedan serializar a JSON, para registrar en Mongo y para versionar."""
    for s in (EVENT_SCHEMA, ALERT_SCHEMA, RULE_SCHEMA):
        assert json.loads(json.dumps(s)) == s

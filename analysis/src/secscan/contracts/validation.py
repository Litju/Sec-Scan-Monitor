"""Bounded validation helpers for FL-002 contract models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypeVar, cast

from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


def load_model(model_type: type[ModelT], payload: dict[str, Any]) -> ModelT:
    """Validate a mapping into an immutable contract model instance."""
    return model_type.model_validate(payload)


def load_model_json(model_type: type[ModelT], payload: str | bytes) -> ModelT:
    """Validate a JSON string or byte payload into a contract model instance."""
    return model_type.model_validate_json(payload)


def dump_model(model: BaseModel) -> dict[str, Any]:
    """Export a model instance as a Python mapping."""
    return model.model_dump(mode="python")


def read_schema(schema_path: Path) -> dict[str, Any]:
    """Read a contract schema file from disk."""
    data: Any = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Schema file must contain a top-level JSON object: {schema_path}")
    return cast(dict[str, Any], data)


def compare_required_fields(
    model_type: type[BaseModel], schema_path: Path
) -> tuple[set[str], set[str]]:
    """Return model and schema required-field sets for bounded fidelity checks."""
    schema = read_schema(schema_path)
    model_schema = model_type.model_json_schema()
    schema_required = set(schema.get("required", []))
    model_required = set(model_schema.get("required", []))
    return model_required, schema_required


def schema_property_names(schema_path: Path) -> set[str]:
    """Return top-level property names from a JSON Schema file."""
    properties = read_schema(schema_path).get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError(f"Schema properties must be an object: {schema_path}")
    return set(properties.keys())
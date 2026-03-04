"""
HoneyMed - Central Configuration Loader
Reads config/settings.yaml and provides it to all layers.
"""

import os
import yaml

_CONFIG = None
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config(config_path: str | None = None) -> dict:
    """Load and cache the YAML configuration."""
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG

    if config_path is None:
        config_path = os.path.join(_BASE_DIR, "config", "settings.yaml")

    with open(config_path, "r") as f:
        _CONFIG = yaml.safe_load(f)

    return _CONFIG


def get_config() -> dict:
    """Return the cached config, loading it if necessary."""
    if _CONFIG is None:
        return load_config()
    return _CONFIG


def get_base_dir() -> str:
    """Return the project root directory."""
    return _BASE_DIR

"""
Настройки валидаторов из окружения, чтобы main и p2p_http использовали единообразно.
"""

import os
from validator import load_validators_from_env, ValidatorConfig


def load_validator_config() -> ValidatorConfig:
    cfg = load_validators_from_env()
    ratio = os.environ.get("VALIDATOR_RATIO")
    if ratio:
        try:
            cfg.threshold_ratio = float(ratio)
        except ValueError:
            pass
    return cfg

"""Build-Offsets. Schluessel: (php_version, distro)."""
import json

TABLE = {
    ("8.2.34", "ubuntu24.04"): {"zif_system": 0x6A4C20, "zval_ptr_dtor": 0x18F3B0},
    ("8.3.35", "ubuntu24.04"): {"zif_system": 0x6B1E40, "zval_ptr_dtor": 0x1926C0},
    ("8.4.26", "ubuntu24.04"): {"zif_system": 0x6C2A90, "zval_ptr_dtor": 0x19A440},
    ("8.4.26", "debian12"):    {"zif_system": 0x6C1F10, "zval_ptr_dtor": 0x19A010},
    ("8.4.26", "docker"):      {"zif_system": 0x6C2A90, "zval_ptr_dtor": 0x19A440},
    ("8.5.11", "ubuntu24.04"): {"zif_system": 0x6D7C50, "zval_ptr_dtor": 0x1A12E0},
}


def resolve(version, distro_hint, override=None):
    if override:
        with open(override) as fh:
            return json.load(fh)
    if not version:
        return None
    for (v, d), off in TABLE.items():
        if version == v and d == (distro_hint or ""):
            return off
    for (v, d), off in TABLE.items():
        if version == v:
            return off
    return None

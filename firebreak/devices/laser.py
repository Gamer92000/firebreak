from __future__ import annotations

from firebreak.plugin import Device, DeviceConfig, Feature

LASER = Device(
    features=frozenset({Feature.AB_SLOTS}),
    models=frozenset({"AEOLS"}),
    name="laser",
    product="laser",
    title="Amazon Echo (4th Generation)",
    unlock_keeps_misc=True,
)
CONFIG = DeviceConfig(device=LASER)

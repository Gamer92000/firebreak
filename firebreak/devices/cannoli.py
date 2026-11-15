from __future__ import annotations

from firebreak.plugin import Device, DeviceConfig, Feature

CANNOLI = Device(
    features=frozenset({Feature.AB_SLOTS, Feature.UBI}),
    models=frozenset({"AEOCA"}),
    name="cannoli",
    product="cannoli",
    title="Echo Dot (5th Generation)",
    twrp_models=frozenset({"Cannoli-TWRP", "omni_cannoli"}),
    unlock_keeps_misc=True,
)
CONFIG = DeviceConfig(device=CANNOLI)

package com.interviewassistant.licensing.domain;

/**
 * State of a device registration. Only {@code ACTIVE} is produced in Phase 128; {@code RESET} is defined so the schema and
 * contract are ready for the controlled device-reset operation, which is deliberately deferred (see the Phase 128 report).
 */
public enum DeviceStatus {
    ACTIVE,
    RESET
}

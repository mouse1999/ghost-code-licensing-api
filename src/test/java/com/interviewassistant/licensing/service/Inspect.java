package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.License;

import java.util.List;
import java.util.UUID;

/** What the tests may look at behind the services' back, so the same tests run on the in-memory store and on PostgreSQL. */
interface Inspect {
    List<AuditEvent> allAudit();      // oldest first

    int licenseCount();

    int countByEmail(String email);

    int deviceCount(UUID licenseId);

    License license(UUID id);

    String dumpEverythingStored();
}

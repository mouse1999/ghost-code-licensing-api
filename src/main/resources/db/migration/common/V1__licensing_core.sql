-- Phase 128: licensing core schema. Portable SQL (PostgreSQL in production, H2 in PostgreSQL mode in tests).
-- Database-enforced rules (so that a coding mistake cannot violate them):
--   * one activation credential per license, credential hashes globally unique;
--   * a device key can be registered once per license;
--   * active_device_count can never exceed device_limit (CHECK), and is only changed by one conditional UPDATE;
--   * status values, device limit, validity and e-mail normalisation are constrained;
--   * every audit/credential/device row references an existing license.

CREATE TABLE license (
    id                      UUID                     NOT NULL,
    customer_email          VARCHAR(254)             NOT NULL,
    status                  VARCHAR(16)              NOT NULL,
    device_limit            INTEGER                  NOT NULL,
    validity_days           INTEGER,
    rights                  VARCHAR(200)             NOT NULL,
    activation_window_days  INTEGER                  NOT NULL,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL,
    activation_deadline     TIMESTAMP WITH TIME ZONE NOT NULL,
    activated_at            TIMESTAMP WITH TIME ZONE,
    expires_at              TIMESTAMP WITH TIME ZONE,
    suspended_at            TIMESTAMP WITH TIME ZONE,
    revoked_at              TIMESTAMP WITH TIME ZONE,
    updated_at              TIMESTAMP WITH TIME ZONE NOT NULL,
    active_device_count     INTEGER                  NOT NULL DEFAULT 0,
    version                 BIGINT                   NOT NULL DEFAULT 0,
    CONSTRAINT pk_license PRIMARY KEY (id),
    CONSTRAINT ck_license_status CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_license_device_limit CHECK (device_limit BETWEEN 1 AND 10),
    CONSTRAINT ck_license_device_count CHECK (active_device_count >= 0 AND active_device_count <= device_limit),
    CONSTRAINT ck_license_validity CHECK (validity_days IS NULL OR validity_days BETWEEN 1 AND 3650),
    CONSTRAINT ck_license_window CHECK (activation_window_days BETWEEN 1 AND 365),
    CONSTRAINT ck_license_email_lower CHECK (customer_email = LOWER(customer_email)),
    CONSTRAINT ck_license_activated CHECK (status <> 'ACTIVE' OR activated_at IS NOT NULL)
);

CREATE INDEX ix_license_email ON license (customer_email);

-- Only a keyed hash of the activation code is stored; the raw code is never persisted.
CREATE TABLE activation_credential (
    license_id  UUID                     NOT NULL,
    code_hash   CHAR(64)                 NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_activation_credential PRIMARY KEY (license_id),
    CONSTRAINT uq_activation_credential_hash UNIQUE (code_hash),
    CONSTRAINT fk_activation_credential_license FOREIGN KEY (license_id) REFERENCES license (id)
);

CREATE TABLE device_registration (
    id                             UUID                     NOT NULL,
    license_id                     UUID                     NOT NULL,
    public_key                     VARCHAR(100)             NOT NULL,
    key_thumbprint                 CHAR(64)                 NOT NULL,
    supplementary_fingerprint_hash CHAR(64),
    label                          VARCHAR(64),
    bound_at                       TIMESTAMP WITH TIME ZONE NOT NULL,
    status                         VARCHAR(8)               NOT NULL,
    reset_at                       TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_device_registration PRIMARY KEY (id),
    CONSTRAINT fk_device_license FOREIGN KEY (license_id) REFERENCES license (id),
    CONSTRAINT uq_device_license_key UNIQUE (license_id, key_thumbprint),
    CONSTRAINT ck_device_status CHECK (status IN ('ACTIVE', 'RESET'))
);

-- Makes administrative issuance idempotent: the same Idempotency-Key never creates a second license.
CREATE TABLE issuance_request (
    key_hash     CHAR(64)                 NOT NULL,
    fingerprint  CHAR(64)                 NOT NULL,
    license_id   UUID                     NOT NULL,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_issuance_request PRIMARY KEY (key_hash),
    CONSTRAINT fk_issuance_license FOREIGN KEY (license_id) REFERENCES license (id)
);

-- Append-only at the application level (no update/delete is ever issued by the code). On PostgreSQL, migration V2 adds
-- triggers that also reject UPDATE, DELETE and TRUNCATE. A database administrator can still defeat either: see the docs.
CREATE TABLE audit_event (
    id           BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    occurred_at  TIMESTAMP WITH TIME ZONE            NOT NULL,
    actor        VARCHAR(100)                        NOT NULL,
    action       VARCHAR(32)                         NOT NULL,
    license_id   UUID,
    outcome      VARCHAR(8)                          NOT NULL,
    detail       VARCHAR(1000)                       NOT NULL,
    CONSTRAINT pk_audit_event PRIMARY KEY (id),
    CONSTRAINT fk_audit_license FOREIGN KEY (license_id) REFERENCES license (id),
    CONSTRAINT ck_audit_outcome CHECK (outcome IN ('SUCCESS', 'FAILURE'))
);

CREATE INDEX ix_audit_license ON audit_event (license_id, id);

-- PostgreSQL only: make audit_event append-only inside the database as well as in the application.
-- This stops accidental or buggy UPDATE/DELETE/TRUNCATE by the application role. It does NOT stop a superuser or the table
-- owner, who can drop the triggers: restrict database access and ship audit rows to separate, write-once storage for real
-- tamper evidence. Also run, once, as the owner:  REVOKE UPDATE, DELETE, TRUNCATE ON audit_event FROM <app_role>;

CREATE FUNCTION audit_event_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_event is append-only (% not permitted)', TG_OP USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_event_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION audit_event_is_append_only();

CREATE TRIGGER trg_audit_event_no_truncate
    BEFORE TRUNCATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION audit_event_is_append_only();

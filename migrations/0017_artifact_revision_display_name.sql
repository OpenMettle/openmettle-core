-- V1-15 migration 17 (ADR 0031): an optional client-supplied file name on each artifact
-- revision, kept strictly as display metadata. Storage locations are derived from the server's
-- reservation UUID alone, never from this column. Additive only: every version 4 to 16 row keeps
-- its values and has no display name. Writers that omit the column keep working unchanged.
ALTER TABLE openmettle.artifact_revisions
    ADD COLUMN display_name text
        CONSTRAINT artifact_revisions_display_name_check
        CHECK (char_length(display_name) BETWEEN 1 AND 255
            AND display_name COLLATE "C" !~ '[[:cntrl:]]'
            AND display_name COLLATE "C" !~ '^[[:space:]]|[[:space:]]$');

-- Immutable like the other revision metadata: written once by `settle`, never updated.
GRANT INSERT (display_name) ON openmettle.artifact_revisions TO openmettle_api, openmettle_worker;

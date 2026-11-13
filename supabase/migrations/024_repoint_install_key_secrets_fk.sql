-- Repoint private.install_key_secrets.key_id to public.install_key_records.
-- Live inserts failed with an FK to a table named install_keys, which no repo migration defines.
-- NOT VALID keeps historical rows from blocking the change while new inserts are enforced.

DO $$
DECLARE
    stale RECORD;
BEGIN
    FOR stale IN
        SELECT con.conname
        FROM pg_constraint AS con
        WHERE con.conrelid = 'private.install_key_secrets'::regclass
          AND con.contype = 'f'
          AND con.confrelid IS DISTINCT FROM 'public.install_key_records'::regclass::oid
    LOOP
        RAISE NOTICE 'dropping stale foreign key % on private.install_key_secrets', stale.conname;
        EXECUTE format('ALTER TABLE private.install_key_secrets DROP CONSTRAINT %I', stale.conname);
    END LOOP;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint AS con
        WHERE con.conrelid = 'private.install_key_secrets'::regclass
          AND con.contype = 'f'
          AND con.confrelid = 'public.install_key_records'::regclass::oid
    ) THEN
        ALTER TABLE private.install_key_secrets
            ADD CONSTRAINT install_key_secrets_key_id_fkey
            FOREIGN KEY (key_id) REFERENCES public.install_key_records (key_id)
            ON DELETE CASCADE NOT VALID;
    END IF;
END;
$$;

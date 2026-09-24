-- Miqaat Core identity schema (structure only, no data) for a FRESH non-production database.
-- Used by scripts/seed-dev-db.ts (hosted demo / test environments such as Render).
-- It already contains the columns and tables added by the oidc_mfa_auth migrations 1790300000000..1790500000000;
-- the seed script records those migrations as applied. Never run it against the real identity database.

--
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: miqaat_core; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA miqaat_core;

--
-- Name: auth_set_updated_at(); Type: FUNCTION; Schema: miqaat_core; Owner: -
--

CREATE FUNCTION miqaat_core.auth_set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
          BEGIN
            NEW.updated_at = now();
            RETURN NEW;
          END $$;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: auth_audit_events; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_audit_events (
    id bigint NOT NULL,
    event_type character varying(64) NOT NULL,
    outcome character varying(16) NOT NULL,
    its_id character varying(64),
    sid character varying(64),
    client_id character varying(64),
    jti character varying(64),
    ip_address character varying(64),
    user_agent character varying(512),
    correlation_id character varying(128),
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_audit_events_outcome_check CHECK (((outcome)::text = ANY ((ARRAY['SUCCESS'::character varying, 'FAILURE'::character varying, 'INFO'::character varying])::text[])))
);

--
-- Name: auth_audit_events_id_seq; Type: SEQUENCE; Schema: miqaat_core; Owner: -
--

CREATE SEQUENCE miqaat_core.auth_audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: auth_audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: miqaat_core; Owner: -
--

ALTER SEQUENCE miqaat_core.auth_audit_events_id_seq OWNED BY miqaat_core.auth_audit_events.id;

--
-- Name: auth_client_callbacks; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_client_callbacks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_ref uuid NOT NULL,
    uri character varying(2048) NOT NULL,
    uri_type character varying(32) NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_client_callbacks_uri_check CHECK (((uri)::text !~ '\*'::text)),
    CONSTRAINT auth_client_callbacks_uri_type_check CHECK (((uri_type)::text = ANY ((ARRAY['CALLBACK'::character varying, 'BACK_CHANNEL_LOGOUT'::character varying, 'POST_LOGOUT_REDIRECT'::character varying])::text[])))
);

--
-- Name: auth_client_handoff_paths; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_client_handoff_paths (
    id bigint NOT NULL,
    client_id character varying(64) NOT NULL,
    path_pattern character varying(512) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_client_handoff_paths_path_pattern_check CHECK ((((path_pattern)::text ~~ '/%'::text) AND ((path_pattern)::text !~~ '//%'::text) AND ((path_pattern)::text !~ '[\\:]'::text)))
);

--
-- Name: auth_client_handoff_paths_id_seq; Type: SEQUENCE; Schema: miqaat_core; Owner: -
--

CREATE SEQUENCE miqaat_core.auth_client_handoff_paths_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: auth_client_handoff_paths_id_seq; Type: SEQUENCE OWNED BY; Schema: miqaat_core; Owner: -
--

ALTER SEQUENCE miqaat_core.auth_client_handoff_paths_id_seq OWNED BY miqaat_core.auth_client_handoff_paths.id;

--
-- Name: auth_client_origins; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_client_origins (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_ref uuid NOT NULL,
    origin character varying(512) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_client_origins_origin_check CHECK (((origin)::text !~ '\*'::text))
);

--
-- Name: auth_clients; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id character varying(64) NOT NULL,
    name character varying(255) NOT NULL,
    application_code character varying(64) NOT NULL,
    application_name character varying(255) NOT NULL,
    business_unit character varying(255),
    utility character varying(255),
    environment character varying(32) NOT NULL,
    client_type character varying(16) DEFAULT 'WEB'::character varying NOT NULL,
    authentication_mode character varying(24) NOT NULL,
    status character varying(24) DEFAULT 'PENDING'::character varying NOT NULL,
    initiate_login_uri character varying(2048),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    auth_realm character varying(16),
    token_endpoint_auth_method character varying(40),
    client_jwks_uri text,
    client_jwks jsonb,
    client_secret_enc text,
    allowed_scopes character varying(255),
    default_acr character varying(64),
    handoff_callback_uri text,
    handoff_inbound_enabled boolean DEFAULT false NOT NULL,
    handoff_outbound_enabled boolean DEFAULT false NOT NULL,
    CONSTRAINT auth_clients_auth_realm_check CHECK (((auth_realm)::text = ANY ((ARRAY['ADMIN'::character varying, 'MUMIN'::character varying])::text[]))),
    CONSTRAINT auth_clients_authentication_mode_check CHECK (((authentication_mode)::text = ANY ((ARRAY['EMBEDDED'::character varying, 'REDIRECT'::character varying, 'EMBEDDED_OR_REDIRECT'::character varying])::text[]))),
    CONSTRAINT auth_clients_client_id_check CHECK (((client_id)::text ~ '^[a-z0-9][a-z0-9-]{2,63}$'::text)),
    CONSTRAINT auth_clients_client_type_check CHECK (((client_type)::text = ANY ((ARRAY['WEB'::character varying, 'SPA'::character varying, 'MOBILE'::character varying, 'SERVICE'::character varying])::text[]))),
    CONSTRAINT auth_clients_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'SECURITY_REVIEW'::character varying, 'ACTIVE'::character varying, 'SUSPENDED'::character varying, 'RETIRED'::character varying])::text[]))),
    CONSTRAINT auth_clients_token_endpoint_auth_method_check CHECK (((token_endpoint_auth_method)::text = ANY ((ARRAY['private_key_jwt'::character varying, 'client_secret_basic'::character varying, 'client_secret_post'::character varying])::text[])))
);

--
-- Name: auth_login_attempts; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_login_attempts (
    id bigint NOT NULL,
    identifier_hash character(64) NOT NULL,
    its_id character varying(64),
    client_id character varying(64),
    ip_address character varying(64),
    success boolean NOT NULL,
    failure_reason character varying(64),
    correlation_id character varying(128),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    attempt_type character varying(16),
    CONSTRAINT auth_login_attempts_attempt_type_check CHECK (((attempt_type)::text = ANY ((ARRAY['LOGIN'::character varying, 'MFA'::character varying])::text[])))
);

--
-- Name: auth_login_attempts_id_seq; Type: SEQUENCE; Schema: miqaat_core; Owner: -
--

CREATE SEQUENCE miqaat_core.auth_login_attempts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: auth_login_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: miqaat_core; Owner: -
--

ALTER SEQUENCE miqaat_core.auth_login_attempts_id_seq OWNED BY miqaat_core.auth_login_attempts.id;

--
-- Name: auth_otp_challenges; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_otp_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    its_id character varying(64) NOT NULL,
    sid character varying(64) NOT NULL,
    interaction_uid character varying(64) NOT NULL,
    channel character varying(8) NOT NULL,
    purpose character varying(16) NOT NULL,
    destination_masked character varying(255) NOT NULL,
    code_hash character(64) NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    provider_message_id character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_otp_challenges_channel_check CHECK (((channel)::text = ANY ((ARRAY['EMAIL'::character varying, 'SMS'::character varying])::text[]))),
    CONSTRAINT auth_otp_challenges_max_attempts_check CHECK ((max_attempts > 0)),
    CONSTRAINT auth_otp_challenges_purpose_check CHECK (((purpose)::text = ANY ((ARRAY['LOGIN_MFA'::character varying, 'STEP_UP'::character varying])::text[])))
);

--
-- Name: auth_session_clients; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_session_clients (
    id bigint NOT NULL,
    sid character varying(64) NOT NULL,
    client_id character varying(64) NOT NULL,
    first_assertion_at timestamp with time zone DEFAULT now() NOT NULL,
    last_assertion_at timestamp with time zone DEFAULT now() NOT NULL,
    assertion_count integer DEFAULT 1 NOT NULL,
    logout_status character varying(16),
    logout_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    established_by character varying(16),
    CONSTRAINT auth_session_clients_established_by_check CHECK (((established_by)::text = ANY ((ARRAY['LOGIN'::character varying, 'HANDOFF'::character varying])::text[]))),
    CONSTRAINT auth_session_clients_logout_status_check CHECK (((logout_status)::text = ANY ((ARRAY['PENDING'::character varying, 'SUCCEEDED'::character varying, 'FAILED'::character varying, 'NO_ENDPOINT'::character varying])::text[])))
);

--
-- Name: auth_session_clients_id_seq; Type: SEQUENCE; Schema: miqaat_core; Owner: -
--

CREATE SEQUENCE miqaat_core.auth_session_clients_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: auth_session_clients_id_seq; Type: SEQUENCE OWNED BY; Schema: miqaat_core; Owner: -
--

ALTER SEQUENCE miqaat_core.auth_session_clients_id_seq OWNED BY miqaat_core.auth_session_clients.id;

--
-- Name: auth_sessions; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.auth_sessions (
    sid character varying(64) NOT NULL,
    its_id character varying(64) NOT NULL,
    auth_method character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    absolute_expires_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoke_reason character varying(64),
    ip_address character varying(64),
    user_agent character varying(512),
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    auth_realm character varying(16),
    session_secret_hash character varying(64),
    status character varying(16),
    aal smallint,
    amr jsonb,
    auth_time timestamp with time zone,
    mfa_verified_at timestamp with time zone,
    mfa_method character varying(16),
    CONSTRAINT auth_sessions_aal_check CHECK ((aal = ANY (ARRAY[1, 2]))),
    CONSTRAINT auth_sessions_auth_realm_check CHECK (((auth_realm)::text = ANY ((ARRAY['ADMIN'::character varying, 'MUMIN'::character varying])::text[]))),
    CONSTRAINT auth_sessions_mfa_method_check CHECK (((mfa_method)::text = ANY ((ARRAY['EMAIL_OTP'::character varying, 'SMS_OTP'::character varying, 'TOTP'::character varying])::text[]))),
    CONSTRAINT auth_sessions_status_check CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'REVOKED'::character varying, 'EXPIRED'::character varying])::text[])))
);

--
-- Name: TABLE auth_sessions; Type: COMMENT; Schema: miqaat_core; Owner: -
--

COMMENT ON TABLE miqaat_core.auth_sessions IS 'Core federation sessions. its_id = users.mumin_id as text; no FK because users is a synced table.';

--
-- Name: handoff_requests; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.handoff_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_client_id character varying(64) NOT NULL,
    target_client_id character varying(64) NOT NULL,
    auth_realm character varying(16) NOT NULL,
    requested_path character varying(512) NOT NULL,
    status character varying(20) DEFAULT 'PENDING'::character varying NOT NULL,
    its_id character varying(64),
    sid character varying(64),
    jti uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT handoff_requests_auth_realm_check CHECK (((auth_realm)::text = ANY ((ARRAY['ADMIN'::character varying, 'MUMIN'::character varying])::text[]))),
    CONSTRAINT handoff_requests_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'COMPLETED'::character varying, 'EXPIRED'::character varying, 'CANCELLED'::character varying])::text[])))
);

--
-- Name: logout_deliveries; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.logout_deliveries (
    job_id uuid NOT NULL,
    client_id character varying(64) NOT NULL,
    jti uuid DEFAULT gen_random_uuid() NOT NULL,
    status character varying(16) DEFAULT 'PENDING'::character varying NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_attempt_at timestamp with time zone,
    last_http_status integer,
    last_error_code character varying(80),
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT logout_deliveries_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'RETRY'::character varying, 'SUCCEEDED'::character varying, 'FAILED'::character varying, 'NO_ENDPOINT'::character varying, 'DEAD'::character varying])::text[])))
);

--
-- Name: logout_jobs; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.logout_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sid character varying(64) NOT NULL,
    its_id character varying(64) NOT NULL,
    auth_realm character varying(16) NOT NULL,
    reason character varying(64) NOT NULL,
    initiated_by_client character varying(64),
    status character varying(24) DEFAULT 'PENDING'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT logout_jobs_auth_realm_check CHECK (((auth_realm)::text = ANY ((ARRAY['ADMIN'::character varying, 'MUMIN'::character varying])::text[]))),
    CONSTRAINT logout_jobs_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'COMPLETED'::character varying, 'COMPLETED_WITH_FAILURES'::character varying])::text[])))
);

--
-- Name: mumin_master; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.mumin_master (
    person_id numeric NOT NULL,
    mumin_id integer NOT NULL,
    first_name character varying(50),
    l_name character varying(50),
    gender character(1),
    email character varying(50),
    jamaat_id numeric,
    fullname character varying(200),
    status_id smallint,
    status character varying(50),
    hof boolean NOT NULL,
    source_row_hash character varying(64) NOT NULL,
    source_run_id uuid NOT NULL,
    source_synced_at timestamp with time zone NOT NULL,
    source_last_seen_at timestamp with time zone NOT NULL,
    is_source_deleted boolean DEFAULT false NOT NULL,
    source_deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: oidc_mfa_auth_migrations; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.oidc_mfa_auth_migrations (
    id integer NOT NULL,
    "timestamp" bigint NOT NULL,
    name character varying NOT NULL
);

--
-- Name: oidc_mfa_auth_migrations_id_seq; Type: SEQUENCE; Schema: miqaat_core; Owner: -
--

CREATE SEQUENCE miqaat_core.oidc_mfa_auth_migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: oidc_mfa_auth_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: miqaat_core; Owner: -
--

ALTER SEQUENCE miqaat_core.oidc_mfa_auth_migrations_id_seq OWNED BY miqaat_core.oidc_mfa_auth_migrations.id;

--
-- Name: signing_key_metadata; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.signing_key_metadata (
    kid character varying(128) NOT NULL,
    alg character varying(16) NOT NULL,
    status character varying(16) NOT NULL,
    jwk_thumbprint character varying(64),
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    status_changed_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    public_jwk jsonb,
    key_provider_ref text,
    purpose character varying(40),
    environment character varying(32),
    activated_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT signing_key_metadata_status_check CHECK (((status)::text = ANY ((ARRAY['NEXT'::character varying, 'ACTIVE'::character varying, 'RETIRING'::character varying, 'RETIRED'::character varying])::text[])))
);

--
-- Name: TABLE signing_key_metadata; Type: COMMENT; Schema: miqaat_core; Owner: -
--

COMMENT ON TABLE miqaat_core.signing_key_metadata IS 'RS256 key metadata only (kid, state). Private keys never live in the database.';

--
-- Name: user_eligible; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.user_eligible (
    id numeric NOT NULL,
    mumin_id integer NOT NULL,
    add_user integer,
    add_date timestamp without time zone,
    source_row_hash character varying(64) NOT NULL,
    source_run_id uuid NOT NULL,
    source_synced_at timestamp with time zone NOT NULL,
    source_last_seen_at timestamp with time zone NOT NULL,
    is_source_deleted boolean DEFAULT false NOT NULL,
    source_deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: user_mfa_factors; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.user_mfa_factors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    its_id character varying(64) NOT NULL,
    method character varying(16) NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    destination_enc text,
    totp_secret_enc text,
    last_used_step bigint,
    status character varying(16) DEFAULT 'ACTIVE'::character varying NOT NULL,
    verified_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_user_mfa_factors_payload CHECK (((((method)::text = 'TOTP'::text) AND (totp_secret_enc IS NOT NULL)) OR (((method)::text <> 'TOTP'::text) AND (destination_enc IS NOT NULL)))),
    CONSTRAINT user_mfa_factors_method_check CHECK (((method)::text = ANY ((ARRAY['EMAIL_OTP'::character varying, 'SMS_OTP'::character varying, 'TOTP'::character varying])::text[]))),
    CONSTRAINT user_mfa_factors_status_check CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'ACTIVE'::character varying, 'DISABLED'::character varying])::text[])))
);

--
-- Name: users; Type: TABLE; Schema: miqaat_core; Owner: -
--

CREATE TABLE miqaat_core.users (
    id numeric NOT NULL,
    mumin_id integer NOT NULL,
    password character varying(100),
    person_master_id numeric,
    password1 character varying(50),
    password_status boolean,
    last_login timestamp without time zone,
    emailstatus boolean,
    flg boolean,
    passchgdate timestamp without time zone,
    loginflag integer,
    user_ipaddress character varying(50),
    forget_password_blocked_date timestamp without time zone,
    is_otprequired boolean NOT NULL,
    add_date timestamp without time zone,
    allow_login boolean,
    source_row_hash character varying(64) NOT NULL,
    source_run_id uuid NOT NULL,
    source_synced_at timestamp with time zone NOT NULL,
    source_last_seen_at timestamp with time zone NOT NULL,
    is_source_deleted boolean DEFAULT false NOT NULL,
    source_deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: auth_audit_events id; Type: DEFAULT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_audit_events ALTER COLUMN id SET DEFAULT nextval('miqaat_core.auth_audit_events_id_seq'::regclass);

--
-- Name: auth_client_handoff_paths id; Type: DEFAULT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_handoff_paths ALTER COLUMN id SET DEFAULT nextval('miqaat_core.auth_client_handoff_paths_id_seq'::regclass);

--
-- Name: auth_login_attempts id; Type: DEFAULT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_login_attempts ALTER COLUMN id SET DEFAULT nextval('miqaat_core.auth_login_attempts_id_seq'::regclass);

--
-- Name: auth_session_clients id; Type: DEFAULT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_session_clients ALTER COLUMN id SET DEFAULT nextval('miqaat_core.auth_session_clients_id_seq'::regclass);

--
-- Name: oidc_mfa_auth_migrations id; Type: DEFAULT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.oidc_mfa_auth_migrations ALTER COLUMN id SET DEFAULT nextval('miqaat_core.oidc_mfa_auth_migrations_id_seq'::regclass);

--
-- Name: oidc_mfa_auth_migrations PK_b89dbb375f046383b377edc545f; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.oidc_mfa_auth_migrations
    ADD CONSTRAINT "PK_b89dbb375f046383b377edc545f" PRIMARY KEY (id);

--
-- Name: auth_audit_events auth_audit_events_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_audit_events
    ADD CONSTRAINT auth_audit_events_pkey PRIMARY KEY (id);

--
-- Name: auth_client_callbacks auth_client_callbacks_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_callbacks
    ADD CONSTRAINT auth_client_callbacks_pkey PRIMARY KEY (id);

--
-- Name: auth_client_handoff_paths auth_client_handoff_paths_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_handoff_paths
    ADD CONSTRAINT auth_client_handoff_paths_pkey PRIMARY KEY (id);

--
-- Name: auth_client_origins auth_client_origins_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_origins
    ADD CONSTRAINT auth_client_origins_pkey PRIMARY KEY (id);

--
-- Name: auth_clients auth_clients_client_id_key; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_clients
    ADD CONSTRAINT auth_clients_client_id_key UNIQUE (client_id);

--
-- Name: auth_clients auth_clients_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_clients
    ADD CONSTRAINT auth_clients_pkey PRIMARY KEY (id);

--
-- Name: auth_login_attempts auth_login_attempts_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_login_attempts
    ADD CONSTRAINT auth_login_attempts_pkey PRIMARY KEY (id);

--
-- Name: auth_otp_challenges auth_otp_challenges_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_otp_challenges
    ADD CONSTRAINT auth_otp_challenges_pkey PRIMARY KEY (id);

--
-- Name: auth_session_clients auth_session_clients_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_session_clients
    ADD CONSTRAINT auth_session_clients_pkey PRIMARY KEY (id);

--
-- Name: auth_sessions auth_sessions_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_sessions
    ADD CONSTRAINT auth_sessions_pkey PRIMARY KEY (sid);

--
-- Name: handoff_requests handoff_requests_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.handoff_requests
    ADD CONSTRAINT handoff_requests_pkey PRIMARY KEY (id);

--
-- Name: logout_deliveries logout_deliveries_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.logout_deliveries
    ADD CONSTRAINT logout_deliveries_pkey PRIMARY KEY (job_id, client_id);

--
-- Name: logout_jobs logout_jobs_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.logout_jobs
    ADD CONSTRAINT logout_jobs_pkey PRIMARY KEY (id);

--
-- Name: mumin_master mumin_master_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.mumin_master
    ADD CONSTRAINT mumin_master_pkey PRIMARY KEY (person_id);

--
-- Name: signing_key_metadata signing_key_metadata_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.signing_key_metadata
    ADD CONSTRAINT signing_key_metadata_pkey PRIMARY KEY (kid);

--
-- Name: auth_client_callbacks uq_auth_client_callbacks_client_uri_type; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_callbacks
    ADD CONSTRAINT uq_auth_client_callbacks_client_uri_type UNIQUE (client_ref, uri, uri_type);

--
-- Name: auth_client_origins uq_auth_client_origins_client_origin; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_origins
    ADD CONSTRAINT uq_auth_client_origins_client_origin UNIQUE (client_ref, origin);

--
-- Name: auth_session_clients uq_auth_session_clients_sid_client; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_session_clients
    ADD CONSTRAINT uq_auth_session_clients_sid_client UNIQUE (sid, client_id);

--
-- Name: auth_client_handoff_paths uq_handoff_paths_client_pattern; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_handoff_paths
    ADD CONSTRAINT uq_handoff_paths_client_pattern UNIQUE (client_id, path_pattern);

--
-- Name: user_eligible user_eligible_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.user_eligible
    ADD CONSTRAINT user_eligible_pkey PRIMARY KEY (id);

--
-- Name: user_mfa_factors user_mfa_factors_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.user_mfa_factors
    ADD CONSTRAINT user_mfa_factors_pkey PRIMARY KEY (id);

--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

--
-- Name: idx_auth_audit_event; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_audit_event ON miqaat_core.auth_audit_events USING btree (event_type, created_at DESC);

--
-- Name: idx_auth_audit_its; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_audit_its ON miqaat_core.auth_audit_events USING btree (its_id, created_at DESC);

--
-- Name: idx_auth_audit_sid; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_audit_sid ON miqaat_core.auth_audit_events USING btree (sid);

--
-- Name: idx_auth_client_callbacks_client; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_client_callbacks_client ON miqaat_core.auth_client_callbacks USING btree (client_ref);

--
-- Name: idx_auth_client_origins_client; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_client_origins_client ON miqaat_core.auth_client_origins USING btree (client_ref);

--
-- Name: idx_auth_otp_challenges_its; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_otp_challenges_its ON miqaat_core.auth_otp_challenges USING btree (its_id, created_at DESC);

--
-- Name: idx_auth_otp_challenges_sid; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_otp_challenges_sid ON miqaat_core.auth_otp_challenges USING btree (sid, interaction_uid);

--
-- Name: idx_auth_sessions_active; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_sessions_active ON miqaat_core.auth_sessions USING btree (its_id) WHERE (revoked_at IS NULL);

--
-- Name: idx_auth_sessions_its; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_sessions_its ON miqaat_core.auth_sessions USING btree (its_id, created_at DESC);

--
-- Name: idx_auth_sessions_its_realm_status; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_auth_sessions_its_realm_status ON miqaat_core.auth_sessions USING btree (its_id, auth_realm, status);

--
-- Name: idx_handoff_paths_client; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_handoff_paths_client ON miqaat_core.auth_client_handoff_paths USING btree (client_id, enabled);

--
-- Name: idx_handoff_pending_expiry; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_handoff_pending_expiry ON miqaat_core.handoff_requests USING btree (status, expires_at);

--
-- Name: idx_login_attempts_identifier; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_login_attempts_identifier ON miqaat_core.auth_login_attempts USING btree (identifier_hash, created_at DESC);

--
-- Name: idx_login_attempts_ip; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_login_attempts_ip ON miqaat_core.auth_login_attempts USING btree (ip_address, created_at DESC);

--
-- Name: idx_login_attempts_its; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_login_attempts_its ON miqaat_core.auth_login_attempts USING btree (its_id, created_at DESC);

--
-- Name: idx_logout_deliveries_due; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_logout_deliveries_due ON miqaat_core.logout_deliveries USING btree (next_attempt_at) WHERE ((status)::text = ANY ((ARRAY['PENDING'::character varying, 'RETRY'::character varying])::text[]));

--
-- Name: idx_logout_jobs_sid; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_logout_jobs_sid ON miqaat_core.logout_jobs USING btree (sid);

--
-- Name: idx_user_mfa_factors_its; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX idx_user_mfa_factors_its ON miqaat_core.user_mfa_factors USING btree (its_id, status);

--
-- Name: ix_mumin_master_mumin_id; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX ix_mumin_master_mumin_id ON miqaat_core.mumin_master USING btree (mumin_id);

--
-- Name: ix_user_eligible_mumin_id; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX ix_user_eligible_mumin_id ON miqaat_core.user_eligible USING btree (mumin_id);

--
-- Name: ix_users_mumin_id; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE INDEX ix_users_mumin_id ON miqaat_core.users USING btree (mumin_id);

--
-- Name: uq_auth_client_single_backchannel; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE UNIQUE INDEX uq_auth_client_single_backchannel ON miqaat_core.auth_client_callbacks USING btree (client_ref) WHERE ((uri_type)::text = 'BACK_CHANNEL_LOGOUT'::text);

--
-- Name: uq_auth_sessions_secret_hash; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE UNIQUE INDEX uq_auth_sessions_secret_hash ON miqaat_core.auth_sessions USING btree (session_secret_hash) WHERE (session_secret_hash IS NOT NULL);

--
-- Name: uq_user_mfa_factors_one_default; Type: INDEX; Schema: miqaat_core; Owner: -
--

CREATE UNIQUE INDEX uq_user_mfa_factors_one_default ON miqaat_core.user_mfa_factors USING btree (its_id) WHERE (is_default AND ((status)::text = 'ACTIVE'::text));

--
-- Name: auth_audit_events trg_auth_audit_events_updated_at; Type: TRIGGER; Schema: miqaat_core; Owner: -
--

CREATE TRIGGER trg_auth_audit_events_updated_at BEFORE UPDATE ON miqaat_core.auth_audit_events FOR EACH ROW EXECUTE FUNCTION miqaat_core.auth_set_updated_at();

--
-- Name: auth_clients trg_auth_clients_updated_at; Type: TRIGGER; Schema: miqaat_core; Owner: -
--

CREATE TRIGGER trg_auth_clients_updated_at BEFORE UPDATE ON miqaat_core.auth_clients FOR EACH ROW EXECUTE FUNCTION miqaat_core.auth_set_updated_at();

--
-- Name: auth_login_attempts trg_auth_login_attempts_updated_at; Type: TRIGGER; Schema: miqaat_core; Owner: -
--

CREATE TRIGGER trg_auth_login_attempts_updated_at BEFORE UPDATE ON miqaat_core.auth_login_attempts FOR EACH ROW EXECUTE FUNCTION miqaat_core.auth_set_updated_at();

--
-- Name: auth_session_clients trg_auth_session_clients_updated_at; Type: TRIGGER; Schema: miqaat_core; Owner: -
--

CREATE TRIGGER trg_auth_session_clients_updated_at BEFORE UPDATE ON miqaat_core.auth_session_clients FOR EACH ROW EXECUTE FUNCTION miqaat_core.auth_set_updated_at();

--
-- Name: auth_sessions trg_auth_sessions_updated_at; Type: TRIGGER; Schema: miqaat_core; Owner: -
--

CREATE TRIGGER trg_auth_sessions_updated_at BEFORE UPDATE ON miqaat_core.auth_sessions FOR EACH ROW EXECUTE FUNCTION miqaat_core.auth_set_updated_at();

--
-- Name: signing_key_metadata trg_signing_key_metadata_updated_at; Type: TRIGGER; Schema: miqaat_core; Owner: -
--

CREATE TRIGGER trg_signing_key_metadata_updated_at BEFORE UPDATE ON miqaat_core.signing_key_metadata FOR EACH ROW EXECUTE FUNCTION miqaat_core.auth_set_updated_at();

--
-- Name: auth_client_callbacks auth_client_callbacks_client_ref_fkey; Type: FK CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_callbacks
    ADD CONSTRAINT auth_client_callbacks_client_ref_fkey FOREIGN KEY (client_ref) REFERENCES miqaat_core.auth_clients(id) ON DELETE CASCADE;

--
-- Name: auth_client_handoff_paths auth_client_handoff_paths_client_id_fkey; Type: FK CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_handoff_paths
    ADD CONSTRAINT auth_client_handoff_paths_client_id_fkey FOREIGN KEY (client_id) REFERENCES miqaat_core.auth_clients(client_id) ON DELETE CASCADE;

--
-- Name: auth_client_origins auth_client_origins_client_ref_fkey; Type: FK CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_client_origins
    ADD CONSTRAINT auth_client_origins_client_ref_fkey FOREIGN KEY (client_ref) REFERENCES miqaat_core.auth_clients(id) ON DELETE CASCADE;

--
-- Name: auth_session_clients auth_session_clients_sid_fkey; Type: FK CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.auth_session_clients
    ADD CONSTRAINT auth_session_clients_sid_fkey FOREIGN KEY (sid) REFERENCES miqaat_core.auth_sessions(sid) ON DELETE CASCADE;

--
-- Name: logout_deliveries logout_deliveries_job_id_fkey; Type: FK CONSTRAINT; Schema: miqaat_core; Owner: -
--

ALTER TABLE ONLY miqaat_core.logout_deliveries
    ADD CONSTRAINT logout_deliveries_job_id_fkey FOREIGN KEY (job_id) REFERENCES miqaat_core.logout_jobs(id) ON DELETE CASCADE;

--
--


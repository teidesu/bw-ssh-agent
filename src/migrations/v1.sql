create table identities (
    -- uuid from bitwarden vault
    id text primary key,
    -- name from bitwarden vault
    name text not null,
    -- public key (in openssh blob format)
    public_key blob not null,
    -- encrypted private key
    private_key text not null
);

create table auth (
    vault_url text not null,
    access_token text not null,
    refresh_token text not null,
    expires_at integer not null,
    -- encrypted with secure enclave master key
    master_key blob not null,
    -- encrypted with secure enclave symmetric key
    symmetric_key blob not null
);
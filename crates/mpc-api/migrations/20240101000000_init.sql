-- crates/mpc-api/migrations/20240101000000_init.sql
-- ============================================================================
-- Initial Database Schema for MPC-RS API Gateway
-- ============================================================================
-- This migration initializes the SQLite database used by the API Gateway to 
-- manage BIP32 derivation state and persist derived addresses for auditing 
-- and fast public key lookups during transaction building.

-- ----------------------------------------------------------------------------
-- Table: key_manager_state
-- ----------------------------------------------------------------------------
-- Maintains the monotonically increasing counters for BIP32 derivation paths.
-- We enforce a singleton pattern (id = 1) to ensure there is only ever one 
-- source of truth for the derivation indices across the entire vault.
-- - external_index: Used for receiving addresses (standard BIP44 path: m/0/*)
-- - internal_index: Used for change addresses (standard BIP44 path: m/1/*)
CREATE TABLE IF NOT EXISTS key_manager_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    external_index INTEGER NOT NULL DEFAULT 0,
    internal_index INTEGER NOT NULL DEFAULT 0
);

-- Idempotent initialization of the singleton state row.
-- If the database is recreated or the migration is run multiple times, 
-- this safely does nothing, preserving the existing indices.
INSERT OR IGNORE INTO key_manager_state (id, external_index, internal_index) 
VALUES (1, 0, 0);

-- ----------------------------------------------------------------------------
-- Table: derived_addresses
-- ----------------------------------------------------------------------------
-- An append-only audit log and lookup table for all addresses derived from 
-- the master vault key. Storing the public key here avoids re-deriving it 
-- from the path during transaction building, and allows reverse lookups 
-- (e.g., finding the public key given a known address).
CREATE TABLE IF NOT EXISTS derived_addresses (
    -- The chain-specific, human-readable address string (e.g., bc1q..., 0x...)
    address TEXT PRIMARY KEY,
    
    -- The exact BIP32 derivation path used to generate this address
    derivation_path TEXT NOT NULL,
    
    -- The hex-encoded raw public key bytes associated with this address
    public_key TEXT NOT NULL,
    
    -- Boolean flag indicating if this is an internal (change) address
    is_change BOOLEAN NOT NULL,
    
    -- Timestamp of when the address was first derived and recorded
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index to optimize reverse lookups (Address -> Public Key/Path)
-- This is critical for the `get_public_key_for_address` handler, which is 
-- called on every transaction signing request to fetch the signer's pubkey.
CREATE INDEX IF NOT EXISTS idx_derived_addresses_address ON derived_addresses(address);

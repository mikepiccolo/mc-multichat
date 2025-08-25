-- Base schema for knowledge base storage (per-tenant) using pgvector
-- Run after: CREATE EXTENSION IF NOT EXISTS vector;

CREATE SCHEMA IF NOT EXISTS kb;

CREATE TABLE IF NOT EXISTS kb.documents (
id           BIGSERIAL PRIMARY KEY,
client_id    TEXT NOT NULL,
source       TEXT NOT NULL,          -- e.g., 'url', 'pdf', 'faq'
uri          TEXT,                   -- canonical source URL or path
title        TEXT,
checksum     TEXT,                   -- for deduping (e.g., sha256)
created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS kb.chunks (
id           BIGSERIAL PRIMARY KEY,
document_id  BIGINT REFERENCES kb.documents(id) ON DELETE CASCADE,
client_id    TEXT NOT NULL,
chunk_index  INT NOT NULL,
content      TEXT NOT NULL,
embedding    VECTOR(1536),           -- set to your embedding dimension
created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chunks_client_doc ON kb.chunks(client_id, document_id);

-- You can create an IVFFLAT index once data is loaded (choose lists appropriately):
-- CREATE INDEX IF NOT EXISTS idx_chunks_embed_ivfflat ON kb.chunks USING ivfflat (embedding vector_l2_ops) WITH (lists = 100);
-- ANALYZE kb.chunks;


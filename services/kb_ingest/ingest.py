#!/usr/bin/env python3
"""Minimal ingestion CLI: URL or file -> chunks -> OpenAI embeddings -> Postgres (pgvector).
Usage:
  python services/kb_ingest/ingest.py --client-id demo-realtor \
    --source url --input https://example.com/faq --title "Example FAQ" --embed-dim 1536

Env:
  PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD  (from Secrets Manager)
  OPENAI_API_KEY                                   (pulled locally for CLI)
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup
import psycopg
from psycopg.rows import dict_row
from openai import OpenAI


def load_text_from_url(url: str) -> str:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    # Drop script/style
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    # Join text with literal newlines and collapse runs
    text = "\n".join(x.strip() for x in soup.get_text("\n").splitlines() if x.strip())
    text = re.sub(r"\n{2,}", "\n\n", text)
    return text


def load_text_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def chunk_text(text: str, target_chars: int = 1200, overlap: int = 150) -> List[str]:
    paras = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: List[str] = []
    cur = ""
    for p in paras:
        if len(cur) + len(p) + 2 <= target_chars:
            cur = (cur + "\n\n" + p) if cur else p
        else:
            if cur:
                chunks.append(cur)
                # overlap
                cur_tail = cur[-overlap:]
                cur = (cur_tail + "\n\n" + p)
            else:
                # very long paragraph, hard-split
                for i in range(0, len(p), target_chars):
                    chunks.append(p[i:i + target_chars])
                cur = ""
    if cur:
        chunks.append(cur)
    return chunks


def ensure_pg_env() -> None:
    missing = [k for k in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD") if not os.getenv(k)]
    if missing:
        raise SystemExit(f"Missing DB env vars: {missing}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--source", choices=["url", "file"], required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--title", default=None)
    ap.add_argument("--embed-dim", type=int, default=1536)
    ap.add_argument("--model", default="text-embedding-3-small")
    args = ap.parse_args()

    ensure_pg_env()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY not set")

    if args.source == "url":
        text = load_text_from_url(args.input)
        uri = args.input
        title = args.title or args.input
    else:
        text = load_text_from_file(args.input)
        uri = os.path.abspath(args.input)
        title = args.title or os.path.basename(args.input)

    chunks = chunk_text(text)
    checksum = hashlib.sha256(text.encode("utf-8")).hexdigest()
    print(f"Loaded text -> {len(text)} chars, {len(chunks)} chunks")

    # Insert document and chunks (without embeddings), then backfill embeddings
    with psycopg.connect(row_factory=dict_row) as conn:
        with conn.transaction():
            doc_row = conn.execute(
                """
                INSERT INTO kb.documents(client_id, source, uri, title, checksum)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (args.client_id, args.source, uri, title, checksum),
            ).fetchone()
            doc_id = doc_row["id"]

            chunk_rows: List[Tuple[int, str]] = []
            for idx, ch in enumerate(chunks):
                row = conn.execute(
                    """
                    INSERT INTO kb.chunks(document_id, client_id, chunk_index, content)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (doc_id, args.client_id, idx, ch),
                ).fetchone()
                chunk_rows.append((row["id"], ch))

    client = OpenAI(api_key=api_key)
    BATCH = 64
    with psycopg.connect(row_factory=dict_row) as conn:
        for i in range(0, len(chunk_rows), BATCH):
            batch = chunk_rows[i:i + BATCH]
            inputs = [c for (_, c) in batch]
            emb = client.embeddings.create(model=args.model, input=inputs)
            vectors = [e.embedding for e in emb.data]
            if not vectors:
                continue
            if len(vectors[0]) != args.embed_dim:
                raise SystemExit(f"Model dim {len(vectors[0])} != --embed-dim {args.embed_dim}")
            with conn.transaction():
                for (row_id, _), vec in zip(batch, vectors):
                    # pgvector accepts text input '[1,2,3]' cast to vector
                    vec_txt = "[" + ",".join(f"{x:.7f}" for x in vec) + "]"
                    conn.execute(
                        "UPDATE kb.chunks SET embedding = %s::vector WHERE id = %s",
                        (vec_txt, row_id),
                    )
            print(f"Embedded {i + len(batch)}/{len(chunk_rows)}")

    print({"ok": True, "document_id": doc_id, "chunks": len(chunk_rows)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
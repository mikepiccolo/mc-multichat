import json
import os
import ssl
import boto3
import pg8000
import logging
import requests

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

def get_secret_json(arn: str):
    logger.info("Fetching secret from ARN: %s", arn);
    sm = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=arn)
    return json.loads(resp["SecretString"])


def db_conn():
    logger.info("Connecting to DB");
    creds = get_secret_json(os.environ["RDS_SECRET_ARN"])
    logger.info("Using RDS host: %s", creds["host"]);
    ctx = ssl.create_default_context()
    logger.info("Created SSL context for RDS connection");
    conn = pg8000.connect(
        user=creds["username"],
        password=creds["password"],
        host=creds["host"],
        port=int(creds["port"]),
        database=creds["dbname"],
        ssl_context=ctx,
    )
    logger.info("Connected to RDS Postgres");
    return conn


def embed(text: str, dim: int): 
    logger.info("Generating embedding for text of %d chars", len(text));
    # Fetch OpenAI key from Secrets Manager
    sm = boto3.client("secretsmanager")
    key = sm.get_secret_value(SecretId=os.environ["OPENAI_SECRET_ARN"])['SecretString']
    logger.info("Using OpenAI key from Secrets Manager");
    # Call OpenAI Embeddings REST API directly (avoids pydantic_core native wheel)
    resp = requests.post(
        "https://api.openai.com/v1/embeddings",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "text-embedding-3-small",
            "input": [text],
        },
        timeout=15,
    )
    logger.info("OpenAI response status: %d", resp.status_code);
    resp.raise_for_status()
    vec = resp.json()["data"][0]["embedding"]
    if len(vec) != dim:
        raise RuntimeError(f"Embedding dimension {len(vec)} != expected {dim}")
    
    logger.info("Generated embedding of dim %d", len(vec));
    return vec


def vector_to_literal(vec):
    logger.info("Converting vector of dim %d to literal", len(vec));
    return "[" + ",".join(f"{x:.7f}" for x in vec) + "]"


def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    try:
        params = event.get("queryStringParameters") or {}
        q = params.get("q")
        client_id = params.get("client_id")
        k = int(params.get("k") or 5)
        if not q or not client_id:
            logger.warning("Missing required parameters q or client_id");
            return {
                "statusCode": 400,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"ok": False, "error": "q and client_id are required"}),
            }

        dim = int(os.environ.get("EMBED_DIM", "1536"))
        qvec = embed(q, dim)
        qlit = vector_to_literal(qvec)

        logger.info("Searching for top %d results for client_id %s", k, client_id);
        with db_conn() as conn:
            with conn.cursor() as cur:
                logger.info("Executing vector search query");
                cur.execute(
                    """
                    SELECT c.id as chunk_id, d.id as document_id, d.title, d.uri,
                           1 - (c.embedding <=> %s::vector) as score,  -- convert distance to similarity-ish
                           substring(c.content for 240) as snippet
                    FROM kb.chunks c
                    JOIN kb.documents d ON d.id = c.document_id
                    WHERE c.client_id = %s AND c.embedding IS NOT NULL
                    ORDER BY c.embedding <=> %s::vector
                    LIMIT %s
                    """,
                    (qlit, client_id, qlit, k),
                )
                cols = [d[0] for d in cur.description]
                rows = [dict(zip(cols, r)) for r in cur.fetchall()]

        return {
            "statusCode": 200,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"ok": True, "hits": rows}, default=str),
        }
    except Exception as e:
        logger.exception("Error processing request: %s", str(e));
        return {
            "statusCode": 500,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"ok": False, "error": str(e)}),
        }
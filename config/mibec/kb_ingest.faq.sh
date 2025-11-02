# python services/kb_ingest/ingest.py \
#   --client-id mibec \
#   --source url --input https://electric-soybean-4b3.notion.site/MIBEC-AI-Frequently-Asked-Questions-FAQ-28b7159aa21480ed9477f617f3d05a92 \
#   --title "MIBEC.AI FAQ" \
#   --embed-dim 1536
python services/kb_ingest/ingest.py \
  --client-id mibec \
  --source file --input config/mibec/MIBEC_FAQ.md \
  --title "MIBEC.AI FAQ" \
  --embed-dim 1536

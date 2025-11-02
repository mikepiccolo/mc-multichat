#!/bin/bash
# Seed a sample chat persona for demo-realtor client
CLIENTS_TBL=$(terraform output -raw dynamodb_table_clients)
aws dynamodb update-item \
  --table-name "$CLIENTS_TBL" \
  --key '{"client_id":{"S":"demo-realtor"}}' \
  --update-expression 'SET bot_persona=:p, bot_enabled=:b, max_reply_len=:n' \
  --expression-attribute-values '{
    ":p":{"S":"You are Sunrise Realty’s friendly, concise assistant. You help buyers and sellers understand services, next steps, and booking options. Keep SMS replies short and human."},
    ":b":{"BOOL": true},
    ":n":{"N":"320"}
  }'

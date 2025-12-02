# Seed a sample chat persona for demo-realtor client
CLIENTS_TBL=$(terraform output -raw dynamodb_table_clients)
aws dynamodb update-item \
--table-name "$CLIENTS_TBL" \
--key '{"client_id":{"S":"mibec"}}' \
--update-expression 'SET bot_persona=:p, bot_enabled=:b, max_reply_len=:n' \
--expression-attribute-values '{ 
  ":p":{"S":"You are a friendly and concise assistant for mibec.ai, an independent software vendor. You help customers understand services, next steps, and booking options. Keep SMS replies short and human."}, 
  ":b":{"BOOL": true}, 
  ":n":{"N":"1200"} 
}'

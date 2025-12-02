CLIENTS_TBL=$(terraform output -raw dynamodb_table_clients)

aws dynamodb update-item \
  --table-name "$CLIENTS_TBL" \
  --key '{"client_id":{"S":"mibec"}}' \
  --update-expression 'SET a2p_approved=:a, messaging_service_sid=:m' \
  --expression-attribute-values '{
    ":a":{"BOOL": true},
    ":m":{"S":"MGd61190ba023d8e52906599eac1478bce"}
  }'

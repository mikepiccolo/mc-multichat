CLIENTS_TBL=$(terraform output -raw dynamodb_table_clients)

aws dynamodb update-item \
  --table-name "$CLIENTS_TBL" \
  --key '{"client_id":{"S":"mibec"}}' \
  --update-expression 'SET lead_agent_enabled=:t, lead_vertical=:v, lead_required_fields=:r, lead_notify_sms_e164=:n' \
  --expression-attribute-values '{
    ":t":{"BOOL": true},
    ":v":{"S":"isv"},
    ":r":{"S":""},
    ":n":{"S":"+12014106922"}
  }'

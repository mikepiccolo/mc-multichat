CLIENTS_TBL=$(terraform output -raw dynamodb_table_clients)

aws dynamodb update-item \
  --table-name "$CLIENTS_TBL" \
  --key '{"client_id":{"S":"mibec"}}' \
  --update-expression 'SET scheduling_enabled=:t, sched_days_ahead=:d, sched_slot_minutes=:m, sched_buffer_minutes=:b, sched_hold_minutes=:h, scheduling_link=:l, sched_source=:s' \
  --expression-attribute-values '{
    ":t":{"BOOL": true},
    ":d":{"S":"7"},
    ":m":{"S":"30"},
    ":b":{"S":"5"},
    ":h":{"S":"15"},
    ":l":{"S":""},
    ":s":{"S":"owner"}
  }'

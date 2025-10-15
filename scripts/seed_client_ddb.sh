# !/bin/bash
# Seed a sample client (optional) 
export CLIENTS_TBL=../infra/terraform/$(terraform output -raw dynamodb_table_clients) 
aws dynamodb put-item \
--table-name "$CLIENTS_TBL" \
--item "file://$1"


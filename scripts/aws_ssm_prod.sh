#!/bin/bash
aws ssm start-session \
    --profile prod \
    --target i-0407e808423dcb1b2 \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --region us-east-1 \
    --parameters \
    '{"portNumber":["5432"],"localPortNumber":["5432"],"host":["mc-multichat-prod-pg-private.csha02iuoxht.us-east-1.rds.amazonaws.com"]}'

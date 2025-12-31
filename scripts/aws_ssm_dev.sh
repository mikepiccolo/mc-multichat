#!/bin/bash
aws ssm start-session \
    --profile dev \
    --target i-05f370a9cece42006 \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --region us-east-1 \
    --parameters \
    '{"portNumber":["5432"],"localPortNumber":["5432"],"host":["mc-multichat-dev-pg-private.cwglusrb45if.us-east-1.rds.amazonaws.com"]}'

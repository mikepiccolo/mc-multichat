resource "aws_dynamodb_table" "clients" {
    name         = "${local.name_prefix}-clients"
    billing_mode = "PAY_PER_REQUEST"
    hash_key     = "client_id"

    attribute { 
        name = "client_id"
        type = "S"
    }

    tags = local.tags
}

# Conversation events per user per client

resource "aws_dynamodb_table" "conversations" {
    name         = "${local.name_prefix}-conversations"
    billing_mode = "PAY_PER_REQUEST"
    hash_key     = "pk"   # e.g., CLIENT#<client_id>#USER#<phone/email>
    range_key    = "sk"   # e.g., TS#

    attribute { 
        name = "pk" 
        type = "S" 
    }

    attribute { 
        name = "sk" 
        type = "S" 
    }

    # GSI to fetch recent conversations by client

    attribute { 
        name = "gsi1pk" 
        type = "S" 
    }
   
    attribute { 
        name = "gsi1sk" 
        type = "S" 
    }

    global_secondary_index {
        name            = "gsi1"
        hash_key        = "gsi1pk"
        range_key       = "gsi1sk"
        projection_type = "ALL"
    }

    tags = local.tags
}

# Map inbound Twilio numbers to client IDs

resource "aws_dynamodb_table" "phone_routes" {
    name         = "${local.name_prefix}-phone-routes"
    billing_mode = "PAY_PER_REQUEST"
    hash_key     = "phone_e164"

    attribute { 
        name = "phone_e164" 
        type = "S" 
    }

    tags = local.tags
}



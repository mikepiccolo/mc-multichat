bucket               = "mc-multichat-tfstate-lower"
key                  = "mc-multichat/terraform.tfstate"
region               = "us-east-1"
dynamodb_table       = "mc-multichat-terraform-locks"
encrypt              = true
workspace_key_prefix = "env"
profile              = "lower"

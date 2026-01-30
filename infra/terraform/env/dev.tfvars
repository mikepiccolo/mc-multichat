# project defaults, dev environment
project="mc-multichat"
env="dev"
aws_region="us-east-1"

# postgres configuration
db_instance_class="db.t4g.micro"
db_allocated_storage_gb=20
db_engine_version="16.8"
db_publicly_accessible=false
db_backup_retention_days=0
db_name = "multichatdev"
db_performance_insights_enabled  = false
db_enhanced_monitoring_interval  = 0

log_level = "DEBUG"
# secure twilio endpoints using Twilio SID
twilio_sid_required = false
# GPT LLM model to use
#model_name = "gpt-4o-mini"
model_name = "gpt-5-mini"
# Max tool loops for orchestrator
max_tool_loops = 5
# conversation history
max_history_turns = "10"
# opt-in keyword for SMS consent
optin_keyword = "hello"

# VPC configuration
vpc_cidr = "10.1.0.0/16"
az_count = 3
nat_per_az = false
enable_ssm_bastion = true
flow_log_retention_days = 7
enable_interface_endpoints = true

# Bastion SSH access CIDRs (empty for SSM-only)
bastion_ssh_cidr = []
enable_bastion = true

# AWS profile to use
aws_profile = "lower"

# api base url for dev
api_base_url = "https://api.dev.mibec.ai"

root_zone_name = "dev.mibec.ai"
# cloudfront legal distribution
legal_subdomain = "legal"
legal_bucket_name = "dev.mibec.ai-legal"
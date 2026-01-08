# project defaults, dev environment
project="mc-multichat"
env="prod"
aws_region="us-east-1"

api_stage="v1"

# postgres configuration
db_instance_class="db.t4g.small"    # scale to db.t4j.medium or large when needed
db_allocated_storage_gb=50          # increase as needed, up to 16TB for gp3
db_max_allocated_storage_gb=200
db_engine_version="16.8"
db_publicly_accessible=false
db_backup_retention_days=14
db_name = "multichatprod"
db_multi_az = false                 # set to true after pilot when onboarding customers
db_skip_final_snapshot = false
db_delete_protection = true
db_maintenance_window = "sun:05:00-sun:06:00"
db_backup_window      = "sun:06:00-sun:07:00"
db_apply_immediately  = false
db_performance_insights_enabled = true
db_performance_insights_retention_period = 7
# db_performance_insights_kms_key_id = null   # omit unless you want your own CMK

db_enhanced_monitoring_interval = 60

log_level = "DEBUG"     # set to INFO or WARNING in prod after stabilization

# secure twilio endpoints using Twilio SID
twilio_sid_required = true
# GPT LLM model to use
model_name = "gpt-4o-mini"
#model_name = "gpt-5-mini"
# Max tool loops for orchestrator
max_tool_loops = 3
# conversation history
max_history_turns = "10"
# opt-in keyword for SMS consent
optin_keyword = "hello"

# VPC configuration
vpc_cidr = "10.2.0.0/16"
az_count = 3
nat_per_az = true
enable_ssm_bastion = true
flow_log_retention_days = 30
enable_interface_endpoints = true

# Bastion SSH access CIDRs (empty for SSM-only)
bastion_ssh_cidr = []
enable_bastion = true

# AWS profile to use
aws_profile = "prod"

# api base url for dev
api_base_url = "https://api.mibec.ai"
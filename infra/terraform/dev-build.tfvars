# project defaults, dev environment
project="mc-multichat"
env="dev"
aws_region="us-east-1"

# postgres configuration
db_instance_class="db.t4g.micro"
db_allocated_storage_gb=20
db_engine_version="16.8"
db_publicly_accessible=true
db_backup_retention_days=0
db_name = "multichatdev"

log_level = "DEBUG"
# secure twilio endpoints using Twilio SID
twilio_sid_required = false

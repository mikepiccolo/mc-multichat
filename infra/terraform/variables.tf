variable "project" {
  description = "Project name prefix"
  type        = string
  default     = "mc-multichat"
}

variable "env" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# API stage name
variable "api_stage" {
  description = "API Gateway stage name"
  type        = string
  default     = "v1"
}

# ---- RDS/Postgres vars ----

variable "db_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "16.3"
}

variable "db_instance_class" {
  description = "DB instance size"
  type        = string
  default     = "db.t4g.micro" # dev-friendly
}

variable "db_allocated_storage_gb" {
  description = "Allocated storage (GiB)"
  type        = number
  default     = 20
}

variable "db_name" {
  description = "Initial database name"
  type        = string
  default     = "multichat"
}

variable "db_master_username" {
  description = "Master username for Postgres"
  type        = string
  default     = "postgres"
}

variable "db_publicly_accessible" {
  description = "Whether the DB gets a public IP (dev)"
  type        = bool
  default     = true
}

variable "db_multi_az" {
  description = "Multi-AZ deployment (prod recommended)"
  type        = bool
  default     = false
}

variable "db_backup_retention_days" {
  description = "Backup retention in days (0 disables backups)"
  type        = number
  default     = 0
}

variable "db_skip_final_snapshot" {
  description = "Skip final snapshot on destroy (dev only)"
  type        = bool
  default     = true
}

variable "db_allow_cidrs" {
  description = "List of CIDR blocks allowed to connect to Postgres"
  type        = list(string)
  default     = ["0.0.0.0/0"] # tighten in prod
}

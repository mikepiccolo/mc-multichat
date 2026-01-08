data "aws_vpc" "default" {
  default = true
}

# data "aws_subnets" "default_vpc_subnets" {
#   filter {
#     name   = "vpc-id"
#     values = [data.aws_vpc.default.id]
#   }
# }

# resource "aws_db_subnet_group" "pg" {
#   name       = "${local.name_prefix}-pg-subnets"
#   subnet_ids = data.aws_subnets.default_vpc_subnets.ids
#   tags       = local.tags
# }

resource "aws_security_group" "pg" {
  name        = "${local.name_prefix}-pg-sg"
  description = "PostgreSQL access"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = var.db_allow_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_db_subnet_group" "pg" {
  name_prefix = "${local.name_prefix}-pg-subnets-"
  subnet_ids  = [for s in aws_subnet.private : s.id]
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "random_password" "rds_master" {
  length  = 32
  special = true
}

resource "aws_db_instance" "pg" {
  identifier                 = "${local.name_prefix}-pg-${var.db_identifier_suffix}"
  engine                     = "postgres"
  engine_version             = var.db_engine_version
  instance_class             = var.db_instance_class
  allocated_storage          = var.db_allocated_storage_gb
  max_allocated_storage      = var.db_max_allocated_storage_gb
  storage_type               = "gp3"
  db_name                    = var.db_name
  username                   = var.db_master_username
  password                   = random_password.rds_master.result
  port                       = 5432
  db_subnet_group_name       = aws_db_subnet_group.pg.name
  vpc_security_group_ids     = [aws_security_group.rds.id]
  publicly_accessible        = var.db_publicly_accessible
  multi_az                   = var.db_multi_az
  backup_retention_period    = var.db_backup_retention_days
  skip_final_snapshot        = var.db_skip_final_snapshot
  deletion_protection        = var.db_delete_protection
  auto_minor_version_upgrade = true
  apply_immediately          = var.db_apply_immediately

  # ---- Observability ----
  performance_insights_enabled = var.db_performance_insights_enabled

  performance_insights_retention_period = var.db_performance_insights_enabled ? var.db_performance_insights_retention_period : null
  performance_insights_kms_key_id       = var.db_performance_insights_enabled ? var.db_performance_insights_kms_key_id : null

  monitoring_interval = var.db_enhanced_monitoring_interval
  monitoring_role_arn = var.db_enhanced_monitoring_interval > 0 ? aws_iam_role.rds_monitoring.arn : null

  tags = local.tags


  lifecycle {
    create_before_destroy = true
    replace_triggered_by  = [aws_db_subnet_group.pg.name]
  }
}


# Lambda SG: egress-only
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-sg-lambda"
  vpc_id      = aws_vpc.main.id
  description = "Lambda to RDS/endpoints/NAT"
  egress { 
    from_port=0 
    to_port=0 
    protocol="-1" 
    cidr_blocks=["0.0.0.0/0"] 
  }
  tags = local.tags
}

# RDS SG: allow from lambda & bastion
resource "aws_security_group" "rds" {
  name_prefix        = "${local.name_prefix}-sg-rds-"
  vpc_id      = aws_vpc.main.id
  description = "Postgres access"
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }
  # optional bastion ingress
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }
  egress { 
    from_port=0 
    to_port=0 
    protocol="-1" 
    cidr_blocks=["0.0.0.0/0"] 
  }
  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "bastion" {
  name        = "${local.name_prefix}-sg-bastion"
  vpc_id      = aws_vpc.main.id
  description = "Bastion"
  # SSH optional
  dynamic "ingress" {
    for_each = length(var.bastion_ssh_cidr) > 0 ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.bastion_ssh_cidr
    }
  }
  egress { 
    from_port=0 
    to_port=0 
    protocol="-1" 
    cidr_blocks=["0.0.0.0/0"] 
  }
  tags = local.tags
}

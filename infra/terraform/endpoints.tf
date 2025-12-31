# Gateway endpoints (free) — attach to private route tables
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for rt in aws_route_table.private : rt.id]
  tags              = merge(local.tags, { Name = "${local.name_prefix}-vpce-s3" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for rt in aws_route_table.private : rt.id]
  tags              = merge(local.tags, { Name = "${local.name_prefix}-vpce-dynamodb" })
}

locals {
  iface_services = [
    "secretsmanager",
    "sts",
    "logs",
    "ssm",
    "ssmmessages",
    "ec2messages"   
  ]
}

resource "aws_vpc_endpoint" "iface" {
  for_each          = var.enable_interface_endpoints ? toset(local.iface_services) : []
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [for s in aws_subnet.private : s.id]
  security_group_ids= [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags              = merge(local.tags, { Name = "${local.name_prefix}-vpce-${each.value}" })
}

resource "aws_security_group" "endpoints" {
  name        = "${local.name_prefix}-sg-vpce"
  description = "Interface endpoints"
  vpc_id      = aws_vpc.main.id
  egress { 
    from_port=0 
    to_port=0 
    protocol="-1" 
    cidr_blocks=["0.0.0.0/0"] 
  }
  ingress {
    description = "From private subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = concat(
    [for s in aws_subnet.private : s.cidr_block],
    [for s in aws_subnet.public  : s.cidr_block]
    ) 
  }
  tags = local.tags
}

data "aws_availability_zones" "available" { state = "available" }

locals {
  azs          = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  public_cidrs = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  private_cidrs= [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i + 8)]
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = merge(local.tags, { Name = "${local.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.tags, { Name = "${local.name_prefix}-igw" })
}

resource "aws_subnet" "public" {
  for_each                = toset(local.azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_cidrs[index(local.azs, each.value)]
  availability_zone       = each.value
  map_public_ip_on_launch = true
  tags = merge(local.tags, { Name = "${local.name_prefix}-public-${each.value}", Tier = "public" })
}

resource "aws_subnet" "private" {
  for_each          = toset(local.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_cidrs[index(local.azs, each.value)]
  availability_zone = each.value
  tags = merge(local.tags, { Name = "${local.name_prefix}-private-${each.value}", Tier = "private" })
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route { 
    cidr_block = "0.0.0.0/0" 
    gateway_id = aws_internet_gateway.igw.id 
  }
  tags = merge(local.tags, { Name = "${local.name_prefix}-rt-public" })
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# Pick a deterministic "first" AZ key for the single-NAT(dev) case
locals {
  first_public_az = sort(local.azs)[0]
}

resource "aws_eip" "nat" {
  for_each = var.nat_per_az ? aws_subnet.public : { (local.first_public_az) = aws_subnet.public[local.first_public_az] }
  domain   = "vpc"
  tags     = merge(local.tags, { Name = "${local.name_prefix}-nat-eip-${each.key}" })
}

resource "aws_nat_gateway" "nat" {
  for_each      = aws_eip.nat
  allocation_id = each.value.id
  subnet_id     = var.nat_per_az ? aws_subnet.public[each.key].id : aws_subnet.public[local.first_public_az].id
  tags          = merge(local.tags, { Name = "${local.name_prefix}-nat-${each.key}" })
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = var.nat_per_az ? aws_nat_gateway.nat[each.key].id : aws_nat_gateway.nat[local.first_public_az].id
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-rt-private-${each.key}" })
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/vpc/${local.name_prefix}/flow"
  retention_in_days = var.flow_log_retention_days
  tags              = local.tags
}

resource "aws_iam_role" "vpc_flow" {
  name               = "${local.name_prefix}-vpc-flow-role"
  assume_role_policy = jsonencode({ Version="2012-10-17", Statement=[{Effect="Allow",Principal={Service="vpc-flow-logs.amazonaws.com"},Action="sts:AssumeRole"}] })
  tags               = local.tags
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "${local.name_prefix}-vpc-flow-policy"
  role = aws_iam_role.vpc_flow.id
  policy = jsonencode({
    Version="2012-10-17", Statement=[{
      Effect="Allow", Action=["logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogGroups","logs:DescribeLogStreams"],
      Resource="*"
    }]
  })
}

resource "aws_flow_log" "this" {
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow.arn
  iam_role_arn         = aws_iam_role.vpc_flow.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
  tags                 = local.tags
}

output "vpc_id"              { value = aws_vpc.main.id }
output "private_subnet_ids"  { value = [for s in aws_subnet.private : s.id] }
output "public_subnet_ids"   { value = [for s in aws_subnet.public  : s.id] }

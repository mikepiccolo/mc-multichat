data "aws_ami" "amazon_linux_2023" {
  owners      = ["137112412989"]
  most_recent = true
  filter { 
    name="name" 
    values=["al2023-ami-*-x86_64"] 
  }
}

resource "aws_iam_role" "bastion" {
  name               = "${local.name_prefix}-bastion-role"
  assume_role_policy = jsonencode({Version="2012-10-17",Statement=[{Effect="Allow",Principal={Service="ec2.amazonaws.com"},Action="sts:AssumeRole"}]})
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "bastion_ssm" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "bastion" {
  name = "${local.name_prefix}-bastion-prof"
  role = aws_iam_role.bastion.name
}

resource "aws_instance" "bastion" {
  count                       = var.enable_bastion ? 1 : 0
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  subnet_id                   = values(aws_subnet.public)[0].id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.bastion.name
  user_data = <<-EOF
    #!/bin/bash
    set -e

    dnf install -y postgresql15 amazon-ssm-agent
    systemctl enable --now amazon-ssm-agent
    EOF  
  tags = merge(local.tags, { Name = "${local.name_prefix}-bastion" })
}

output "bastion_instance_id" {
  value = try(aws_instance.bastion[0].id, null)
}
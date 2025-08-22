terraform {
    required_version = ">= 1.6"
    required_providers {
        aws = {
            source  = "hashicorp/aws"
            version = "> 5.60"
        }
        archive = {
            source  = "hashicorp/archive"
            version = "> 2.5"
            }
    }
}

provider "aws" {
    region = var.aws_region
}
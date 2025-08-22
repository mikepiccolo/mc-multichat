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
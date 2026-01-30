data "aws_route53_zone" "root" {
  name         = var.root_zone_name
  private_zone = false
}

locals {
  legal_fqdn = "${var.legal_subdomain}.${trim(var.root_zone_name, ".")}"
}

resource "aws_acm_certificate" "legal" {
  domain_name       = local.legal_fqdn
  validation_method = "DNS"
  tags              = local.tags
}

resource "aws_route53_record" "legal_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.legal.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }

  zone_id = data.aws_route53_zone.root.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.value]
}

resource "aws_acm_certificate_validation" "legal" {
  certificate_arn         = aws_acm_certificate.legal.arn
  validation_record_fqdns = [for r in aws_route53_record.legal_cert_validation : r.fqdn]
}

resource "aws_s3_bucket" "legal" {
  bucket = var.legal_bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "legal" {
  bucket                  = aws_s3_bucket.legal.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "legal" {
  bucket = aws_s3_bucket.legal.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_cloudfront_origin_access_control" "legal" {
  name                              = "legal-oac-${replace(local.legal_fqdn, ".", "-")}"
  description                       = "OAC for legal site S3 origin"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_function" "legal_rewrite" {
  name    = "legal-rewrite-${replace(local.legal_fqdn, ".", "-")}"
  runtime = "cloudfront-js-1.0"
  publish = true
  code    = file("${path.module}/../../cloudfront/legal_rewrite.js")
  comment = "Rewrite /brand -> /brand/ and /brand/ -> /brand/index.html"
}

resource "aws_cloudfront_distribution" "legal" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Legal policies distribution for ${local.legal_fqdn}"
  default_root_object = "index.html"

  aliases = [local.legal_fqdn]

  origin {
    domain_name              = aws_s3_bucket.legal.bucket_regional_domain_name
    origin_id                = "s3-legal-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.legal.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-legal-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    compress              = true

    # Attach the viewer-request function here
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.legal_rewrite.arn
    }

    forwarded_values {
      query_string = true
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 300
    max_ttl     = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.legal.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = local.tags

  depends_on = [aws_acm_certificate_validation.legal]
}

data "aws_iam_policy_document" "legal_bucket_policy" {
  statement {
    sid     = "AllowCloudFrontReadOAC"
    effect  = "Allow"
    actions = ["s3:GetObject"]

    resources = ["${aws_s3_bucket.legal.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.legal.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "legal" {
  bucket = aws_s3_bucket.legal.id
  policy = data.aws_iam_policy_document.legal_bucket_policy.json
}

resource "aws_route53_record" "legal_alias" {
  zone_id = data.aws_route53_zone.root.zone_id
  name    = local.legal_fqdn
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.legal.domain_name
    zone_id                = aws_cloudfront_distribution.legal.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "legal_alias_aaaa" {
  zone_id = data.aws_route53_zone.root.zone_id
  name    = local.legal_fqdn
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.legal.domain_name
    zone_id                = aws_cloudfront_distribution.legal.hosted_zone_id
    evaluate_target_health = false
  }
}

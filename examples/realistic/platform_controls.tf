resource "aws_kms_key" "personal_data" {
  description             = "KMS key for personal data stores"
  deletion_window_in_days = 30
}

resource "aws_db_instance" "customer" {
  allocated_storage       = 20
  engine                  = "postgres"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.personal_data.arn
  backup_retention_period = 14
  deletion_protection     = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = "customer-evidence-vault"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.personal_data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_cloudwatch_metric_alarm" "security_incident" {
  alarm_name          = "security-incident-sev1"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  alarm_description   = "Incident response alert for possible breach events"
}

resource "aws_guardduty_detector" "main" {
  enable = true
}


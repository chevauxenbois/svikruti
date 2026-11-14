resource "aws_kms_key" "personal_data" {
  description             = "KMS key for applicant and repayment data"
  deletion_window_in_days = 30
}

resource "aws_db_instance" "lendflow" {
  engine                  = "postgres"
  allocated_storage       = 50
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.personal_data.arn
  backup_retention_period = 14
  deletion_protection     = true
  publicly_accessible     = false
}

resource "aws_s3_bucket_public_access_block" "kyc_documents" {
  bucket                  = "lendflow-kyc-documents"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/lendflow/app"
  retention_in_days = 365
}

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_secretsmanager_secret" "field_key" {
  name       = "lendflow/field-encryption-key"
  kms_key_id = aws_kms_key.personal_data.arn
}

resource "aws_cloudwatch_metric_alarm" "security_incident" {
  alarm_name          = "security-incident-sev1"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  alarm_description   = "Pages the on-call incident response lead for possible breach events"
}

resource "aws_db_instance" "analytics_replica" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_s3_bucket" "raw_exports" {
  bucket = "svikruti-demo-raw-exports"
  acl    = "public-read"
}

variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "inner" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_versioning" "inner" {
  bucket = aws_s3_bucket.inner.id
  versioning_configuration {
    status = "Enabled"
  }
}

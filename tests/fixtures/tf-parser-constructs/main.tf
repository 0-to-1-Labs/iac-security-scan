variable "buckets" {
  type    = set(string)
  default = ["alpha", "beta"]
}

variable "ingress_ports" {
  type    = list(number)
  default = [443, 8443]
}

resource "aws_s3_bucket" "each" {
  for_each = var.buckets
  bucket   = "demo-${each.value}"
}

resource "aws_security_group" "dyn" {
  name = "dyn-sg"

  dynamic "ingress" {
    for_each = var.ingress_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}

module "storage" {
  source      = "./modules/bucket"
  bucket_name = "module-managed-bucket"
}

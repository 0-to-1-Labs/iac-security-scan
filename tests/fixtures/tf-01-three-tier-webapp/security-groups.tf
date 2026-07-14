# Security Group for ALB
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-${var.environment}-alb-sg"
  }
}

# ALB Inbound Rules - HTTP
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTP from internet"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "allow-http-inbound"
  }
}

# ALB Inbound Rules - HTTPS (Security Flaw: allowing 0.0.0.0/0)
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS from internet"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "allow-https-inbound"
  }
}

# ALB Outbound Rules
resource "aws_vpc_security_group_egress_rule" "alb_all" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow all outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "allow-all-outbound"
  }
}

# Security Group for Application Servers
resource "aws_security_group" "app" {
  name        = "${var.project_name}-${var.environment}-app-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-${var.environment}-app-sg"
  }
}

# App Server Inbound Rules - HTTP from ALB
resource "aws_vpc_security_group_ingress_rule" "app_http_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Allow HTTP from ALB"
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id

  tags = {
    Name = "allow-http-from-alb"
  }
}

# App Server Inbound Rules - HTTPS from ALB
resource "aws_vpc_security_group_ingress_rule" "app_https_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Allow HTTPS from ALB"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id

  tags = {
    Name = "allow-https-from-alb"
  }
}

# App Server Outbound Rules
resource "aws_vpc_security_group_egress_rule" "app_all" {
  security_group_id = aws_security_group.app.id
  description       = "Allow all outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "allow-all-outbound"
  }
}

# Security Group for RDS
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-${var.environment}-rds-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-${var.environment}-rds-sg"
  }
}

# RDS Inbound Rules - MySQL from App Servers
resource "aws_vpc_security_group_ingress_rule" "rds_mysql_app" {
  security_group_id            = aws_security_group.rds.id
  description                  = "Allow MySQL from app servers"
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.app.id

  tags = {
    Name = "allow-mysql-from-app"
  }
}

# RDS Outbound Rules (minimal, database shouldn't need outbound)
resource "aws_vpc_security_group_egress_rule" "rds_all" {
  security_group_id = aws_security_group.rds.id
  description       = "Allow all outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "allow-all-outbound"
  }
}

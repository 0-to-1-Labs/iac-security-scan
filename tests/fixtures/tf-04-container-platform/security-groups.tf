resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-${var.environment}-alb-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"

  description = "Allow HTTP traffic from internet"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"

  description = "Allow HTTPS traffic from internet"
}

resource "aws_vpc_security_group_egress_rule" "alb_all" {
  security_group_id = aws_security_group.alb.id

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  description = "Allow all outbound traffic"
}

resource "aws_security_group" "ecs_tasks" {
  name        = "${var.project_name}-${var.environment}-ecs-tasks-sg"
  description = "Security group for ECS tasks"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-${var.environment}-ecs-tasks-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ecs_tasks_from_alb" {
  security_group_id = aws_security_group.ecs_tasks.id

  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = var.app_port
  to_port                      = var.app_port
  ip_protocol                  = "tcp"

  description = "Allow traffic from ALB"
}

resource "aws_vpc_security_group_ingress_rule" "ecs_tasks_internal" {
  security_group_id = aws_security_group.ecs_tasks.id

  referenced_security_group_id = aws_security_group.ecs_tasks.id
  ip_protocol                  = "-1"

  description = "Allow traffic between ECS tasks"
}

resource "aws_vpc_security_group_egress_rule" "ecs_tasks_all" {
  security_group_id = aws_security_group.ecs_tasks.id

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  description = "Allow all outbound traffic"
}

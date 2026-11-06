# PostgreSQL for the control plane (lineage graph, consent ledger, jobs, certificates).
# The master password is generated and stored in Secrets Manager by RDS.

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "Control-plane PostgreSQL"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_tasks" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.tasks.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_db_parameter_group" "this" {
  name   = local.name
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "this" {
  identifier                  = local.name
  engine                      = "postgres"
  engine_version              = "16"
  instance_class              = var.db_instance_class
  allocated_storage           = var.db_allocated_storage
  storage_encrypted           = true
  db_name                     = "dpdp"
  username                    = "dpdp_admin"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.this.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  parameter_group_name        = aws_db_parameter_group.this.name
  multi_az                    = var.db_multi_az
  backup_retention_period     = 7
  deletion_protection         = var.db_deletion_protection
  skip_final_snapshot         = !var.db_deletion_protection
  final_snapshot_identifier   = var.db_deletion_protection ? "${local.name}-final" : null
  auto_minor_version_upgrade  = true
  publicly_accessible         = false
}

resource "aws_vpc_security_group_ingress_rule" "db_from_agents" {
  for_each                     = toset(var.agent_security_group_ids)
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

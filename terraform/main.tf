provider "aws" {
  region = "us-east-1"
}


terraform {
  backend "s3" {
    bucket         = "terraform-tfstate-file-testt"
    key            = "terraform.tfstate" # Path in the bucket
    region         = "us-east-1"
    encrypt        = true
  }
}

# Генерация случайного суффикса для уникальных имен
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
  numeric = true
}

resource "random_string" "secret_suffix" {
  length  = 8
  special = false
  upper   = false
  numeric = true
}

# EC2 instance to host Nginx
resource "aws_instance" "container_instance" {
  ami           = "ami-0453ec754f44f9a4a"  # Use a suitable AMI for EC2 instance
  instance_type = "t3.small"               # Instance type

  security_groups = [aws_security_group.container_sg.name]
  iam_instance_profile = aws_iam_instance_profile.container_iam_profile.name

  user_data = <<-EOF
              #!/bin/bash
              # Install Nginx
              yum update -y
              yum install -y nginx
              # Set up SSH key for access
              mkdir -p /home/ec2-user/.ssh
              echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC49GsrehH2eksN1KXAeWxPz9RkYxvX7j4PmPsHTnWmgFR6yIMarbI9393KtY1i4gCTJ9LNePqXOn0X1KPz0WYI2rAndRv5vXUHPD8LNMk2HSCjJJPEMWe04R4tChnebahFHbk6mc6hcbzHEOI1OKwE46USboy6C1xGZpLTvkNRJ/+s+wmQbfHOtr5JEsKRWhB4n8682ozHvYFrMnuShnAncovlab/jfFNAbNFUyqlg3hyYOkHZZMdKwVt6xZnXmeCvqKRFbvjk09WjpNNfOdT3GTyEflGWF4bgyz43qeVlaq9oPFOKrs2/R4n+YWK5+0rJCalA3zXR1K8le7tHnIDYTScB3P/FDghlVRZayY56RVZjbRcXk2L1F5qh3pZDyDUI27BvligE8vN5QEpJn2mCZE6P3wX2h9Obe7eHcUxJgkD0lg3yx1Dx3P7Mmi657p8NIdCOGsv3Lm47UovpguN5dhoMIzI1ZjBzerBzkFafSuyZrzMzQ5/YAfHdve+MRyMnQ8EfuZje/hho1qZH4YA+ZAk4xSuQ5bbf50pJbx+D4aMgAPvWZZIteDePwRMOvIn1gB/F3gi9bdsYlaIsOxDXNQfQeHJUqvkIq8fWE2TpfGn7rsg8m0k6RttA0vGkBlGBiVQq3YMZAFkxrn/Iuc+3IfgiL7QpGP28w+/7bJ9cqw== ahmad@DESKTOP-BVAMA07" >> /home/ec2-user/.ssh/authorized_keys
              chmod 600 /home/ec2-user/.ssh/authorized_keys
              chown -R ec2-user:ec2-user /home/ec2-user/.ssh
              # Download Nginx configuration from S3
              aws s3 cp s3://my-config-bucket-${random_string.bucket_suffix.id}/nginx.conf /etc/nginx/nginx.conf
              # Start Nginx service
              systemctl start nginx
              systemctl enable nginx
              # Configure SSH to listen on port 443
              sed -i 's/#Port 22/Port 443/' /etc/ssh/sshd_config
              systemctl restart sshd
              EOF

  tags = {
    Name = "ContainerInstance"
  }
}

# Security group for HTTPS access
resource "aws_security_group" "container_sg" {
  name_prefix = "container_sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow from anywhere
  }

  # Deny all other inbound traffic (default action)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM role for EC2 instance
resource "aws_iam_role" "container_iam_role" {
  name = "container_iam_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# IAM instance profile
resource "aws_iam_instance_profile" "container_iam_profile" {
  name = "container_iam_profile"
  role = aws_iam_role.container_iam_role.name
}

# IAM policy for S3 and Secrets Manager access
resource "aws_iam_policy" "access_policy" {
  name        = "AccessPolicy"
  description = "Allow access to S3 and Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = [
          "secretsmanager:GetSecretValue",
          "s3:GetObject"
        ]
        Effect    = "Allow"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "access_policy_attachment" {
  policy_arn = aws_iam_policy.access_policy.arn
  role       = aws_iam_role.container_iam_role.name
}

# Store environment variables in Secrets Manager
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "db_credentials_${random_string.secret_suffix.id}"
  recovery_window_in_days = 0
}

# Secrets Manager secret version
resource "aws_secretsmanager_secret_version" "secret_version" {
  secret_id     = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    DATABASE_USERNAME = "myuser"
    DATABASE_PASSWORD = "mypassword"
  })
}

resource "random_id" "bucket_id" {
  byte_length = 8
}

# S3 bucket for Nginx config
resource "aws_s3_bucket" "nginx_config_bucket" {
  bucket = "my-config-bucket-${random_string.bucket_suffix.id}"
}

# Upload Nginx configuration file to S3
resource "aws_s3_bucket_object" "nginx_config" {
  bucket = aws_s3_bucket.nginx_config_bucket.bucket
  key    = "nginx.conf"
  source = "nginx.conf"
  acl    = "private"
}

output "nginx_config_bucket_name" {
  value = aws_s3_bucket.nginx_config_bucket.bucket
}

output "nginx_config_object_key" {
  value = aws_s3_bucket_object.nginx_config.key
}

output "nginx_config_object_arn" {
  value = aws_s3_bucket_object.nginx_config.arn
}

output "container_instance_public_ip" {
  value = aws_instance.container_instance.public_ip
}

output "container_instance_id" {
  value = aws_instance.container_instance.id
}

output "secret_name" {
  value = aws_secretsmanager_secret.db_credentials.name
}

output "secret_arn" {
  value = aws_secretsmanager_secret.db_credentials.arn
}

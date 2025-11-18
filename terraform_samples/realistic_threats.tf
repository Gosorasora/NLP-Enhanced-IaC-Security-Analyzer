# 현실적인 보안 위협 시나리오
# 실제 환경에서 발견될 수 있는 교묘한 네이밍과 권한 설정

# 1. 정상적으로 보이지만 위험한 서비스 계정
resource "aws_iam_user" "data_pipeline_service" {
  name = "data-pipeline-prod-svc"
  
  tags = {
    Environment = "production"
    Team        = "data-engineering"
    Purpose     = "automated data processing"
    Owner       = "john.doe@company.com"
  }
}

# 2. 개발자가 "임시로" 만든 계정 (하지만 계속 사용)
resource "aws_iam_user" "dev_testing_account" {
  name = "dev-testing-temp"
  
  tags = {
    Environment = "development"
    Created     = "2024-01-15"
    Purpose     = "development testing"
    # 만료일이 없음 - 위험!
  }
}

# 3. 벤더 계정 (외부 업체용)
resource "aws_iam_user" "vendor_integration" {
  name = "vendor-api-integration"
  
  tags = {
    Type        = "vendor"
    Company     = "DataCorp Solutions"
    Contact     = "support@datacorp.com"
    Environment = "production"
  }
}

# 4. 모니터링용으로 보이지만 과도한 권한
resource "aws_iam_role" "monitoring_service_role" {
  name = "monitoring-service-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_user.data_pipeline_service.arn
        }
      }
    ]
  })
  
  tags = {
    Purpose = "system monitoring and alerting"
    Team    = "devops"
  }
}

# 5. 백업용으로 보이는 역할
resource "aws_iam_role" "backup_automation_role" {
  name = "backup-automation-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_user.dev_testing_account.arn,
            aws_iam_user.vendor_integration.arn
          ]
        }
      }
    ]
  })
  
  tags = {
    Purpose = "automated backup operations"
    Schedule = "daily"
  }
}

# 6. CI/CD용 계정 (하지만 과도한 권한)
resource "aws_iam_user" "cicd_deployment" {
  name = "cicd-deployment-bot"
  
  tags = {
    Type        = "automation"
    Purpose     = "continuous deployment"
    Environment = "all"  # 모든 환경 접근 - 위험!
  }
}

# 7. 정상적으로 보이는 정책 연결들
resource "aws_iam_user_policy_attachment" "data_pipeline_s3" {
  user       = aws_iam_user.data_pipeline_service.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_user_policy_attachment" "dev_testing_ec2" {
  user       = aws_iam_user.dev_testing_account.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

# 8. 교묘하게 숨겨진 관리자 권한
resource "aws_iam_role_policy_attachment" "monitoring_cloudwatch" {
  role       = aws_iam_role.monitoring_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}

# 이것이 진짜 위험! 모니터링 역할에 IAM 권한
resource "aws_iam_role_policy_attachment" "monitoring_iam_readonly" {
  role       = aws_iam_role.monitoring_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

# 9. 백업 역할에 과도한 권한
resource "aws_iam_role_policy_attachment" "backup_admin" {
  role       = aws_iam_role.backup_automation_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # 백업인데 왜 관리자 권한?
}

# 10. CI/CD에 위험한 권한
resource "aws_iam_user_policy_attachment" "cicd_iam_full" {
  user       = aws_iam_user.cicd_deployment.name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

# 11. 교묘한 인라인 정책 - 정상적으로 보이지만 위험
resource "aws_iam_user_policy" "vendor_limited_access" {
  name = "vendor-limited-s3-access"
  user = aws_iam_user.vendor_integration.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::company-data/*",
          "arn:aws:s3:::company-data"
        ]
      },
      {
        # 숨겨진 위험한 권한
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:PassRole",
          "sts:AssumeRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# 12. 개발 계정의 "임시" 정책
resource "aws_iam_user_policy" "dev_temp_permissions" {
  name = "dev-temporary-testing-policy"
  user = aws_iam_user.dev_testing_account.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:*",
          "rds:*",
          "lambda:*",
          # 개발자가 "실수로" 추가한 위험한 권한
          "iam:CreateRole",
          "iam:AttachRolePolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

# 13. 크로스 계정 접근 (정상적으로 보이지만 위험)
resource "aws_iam_role" "cross_account_access" {
  name = "partner-integration-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"  # 외부 계정
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "partner-external-id"
          }
        }
      }
    ]
  })
  
  tags = {
    Purpose = "partner data integration"
    Partner = "TrustedPartner Inc"
  }
}

resource "aws_iam_role_policy_attachment" "cross_account_s3" {
  role       = aws_iam_role.cross_account_access.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# 하지만 실제로는...
resource "aws_iam_role_policy_attachment" "cross_account_hidden_admin" {
  role       = aws_iam_role.cross_account_access.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"  # 숨겨진 강력한 권한
}
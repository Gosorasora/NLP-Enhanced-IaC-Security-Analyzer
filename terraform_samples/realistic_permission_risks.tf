# Realistic Permission Risk Analysis Scenario
# 실제 현업에서 발생할 수 있는 권한 설정 위험들

# 1. CI/CD 서비스 계정 - 과도한 권한
resource "aws_iam_user" "jenkins_service" {
  name = "jenkins-ci-service"
  
  tags = {
    Purpose = "CI/CD automation"
    Team    = "devops"
  }
}

# Jenkins에 관리자 권한 부여 (매우 흔한 실수)
resource "aws_iam_user_policy_attachment" "jenkins_admin" {
  user       = aws_iam_user.jenkins_service.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  # 실제로는 S3, ECR, ECS 권한만 필요한데 편의상 전체 권한 부여
}

# 2. 백업 서비스 - 불필요한 IAM 권한
resource "aws_iam_user" "backup_service" {
  name = "backup-automation"
  
  tags = {
    Service = "backup"
    Critical = "true"
  }
}

resource "aws_iam_user_policy" "backup_policy" {
  name = "backup-service-policy"
  user = aws_iam_user.backup_service.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # 백업을 위한 정상적인 권한
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "rds:CreateDBSnapshot"
        ]
        Resource = "*"
      },
      {
        # 왜 백업 서비스가 IAM 권한이 필요한가? (의심스러운 권한)
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:GetUser",
          "iam:CreateAccessKey"  # ← 특히 위험한 권한
        ]
        Resource = "*"
      }
    ]
  })
}

# 3. 모니터링 서비스 - 읽기 전용이어야 하는데 쓰기 권한
resource "aws_iam_user" "monitoring_service" {
  name = "datadog-monitoring"
  
  tags = {
    Service = "monitoring"
    Vendor  = "datadog"
  }
}

resource "aws_iam_user_policy" "monitoring_policy" {
  name = "monitoring-permissions"
  user = aws_iam_user.monitoring_service.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # 모니터링을 위한 읽기 권한 (정상)
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "ec2:DescribeInstances",
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      },
      {
        # 왜 모니터링 서비스가 쓰기 권한이 필요한가? (의심스러운 권한)
        Effect = "Allow"
        Action = [
          "ec2:TerminateInstances",  # ← 매우 위험!
          "rds:DeleteDBInstance",    # ← 매우 위험!
          "s3:DeleteObject"          # ← 위험!
        ]
        Resource = "*"
      }
    ]
  })
}

# 4. 개발자 계정 - 프로덕션 접근 권한
resource "aws_iam_user" "developer_john" {
  name = "john.smith"
  
  tags = {
    Team = "backend"
    Level = "senior"
  }
}

# 개발자에게 프로덕션 환경 접근 권한 (위험)
resource "aws_iam_user_policy" "dev_prod_access" {
  name = "developer-prod-access"
  user = aws_iam_user.developer_john.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:*",
          "rds:*",
          "s3:*"
        ]
        Resource = "*"
        # 프로덕션 환경에 대한 제한이 없음!
      }
    ]
  })
}

# 5. 람다 실행 역할 - 과도한 권한
resource "aws_iam_role" "lambda_execution" {
  name = "lambda-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# 람다가 실제로는 S3만 접근하면 되는데 전체 권한
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  # 실제로는 S3:GetObject만 필요한 간단한 함수인데...
}

# 6. 크로스 계정 역할 - 너무 광범위한 신뢰 관계
resource "aws_iam_role" "cross_account_role" {
  name = "partner-integration-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          # 특정 계정 대신 모든 계정을 신뢰 (매우 위험!)
          AWS = "*"
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId": "partner-2024"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cross_account_policy" {
  name = "partner-access-policy"
  role = aws_iam_role.cross_account_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::partner-data/*"
      },
      {
        # 파트너 통합을 위해 왜 IAM 권한이 필요한가?
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:PassRole"  # ← 권한 상승 위험!
        ]
        Resource = "*"
      }
    ]
  })
}

# 7. 시간 기반 분석을 위한 메타데이터
resource "aws_iam_user" "intern_account" {
  name = "summer.intern.2023"
  
  tags = {
    Type = "temporary"
    StartDate = "2023-06-01"
    EndDate = "2023-08-31"  # ← 이미 만료됨!
    Manager = "john.smith@company.com"
  }
}

# 인턴 계정에 여전히 권한이 있음 (시간 기반 위험)
resource "aws_iam_user_policy_attachment" "intern_access" {
  user       = aws_iam_user.intern_account.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# 8. 사용 패턴 분석을 위한 시나리오
resource "aws_iam_user" "api_service" {
  name = "api-gateway-service"
  
  tags = {
    Service = "api-gateway"
    LastUsed = "2023-12-01"  # ← 10개월 전 마지막 사용
    Purpose = "legacy-api"
  }
}

# 오래된 서비스인데 여전히 강력한 권한 보유
resource "aws_iam_user_policy" "api_service_policy" {
  name = "api-service-permissions"
  user = aws_iam_user.api_service.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:*",
          "s3:*",
          "lambda:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# 실제 권한 위험 분석 포인트들:
#
# 1. 권한 과다 할당 (Privilege Escalation)
#    - CI/CD 서비스에 AdministratorAccess
#    - 람다에 불필요한 전체 권한
#
# 2. 목적과 맞지 않는 권한 (Purpose Mismatch)
#    - 백업 서비스의 IAM 권한
#    - 모니터링 서비스의 삭제 권한
#
# 3. 환경 분리 실패 (Environment Isolation)
#    - 개발자의 프로덕션 접근
#    - 스테이징과 프로덕션 권한 혼재
#
# 4. 시간 기반 위험 (Temporal Risks)
#    - 만료된 인턴 계정의 활성 권한
#    - 장기간 미사용 서비스 계정
#
# 5. 크로스 계정 위험 (Cross-Account Risks)
#    - 과도하게 광범위한 신뢰 관계
#    - 외부 계정의 내부 IAM 접근
#
# 6. 권한 상승 경로 (Privilege Escalation Paths)
#    - PassRole + AssumeRole 조합
#    - CreateAccessKey 권한의 위험성
# ============================================================================
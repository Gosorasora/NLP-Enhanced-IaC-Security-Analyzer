# Time-Based and Context-Based Risk Detection Demo
# NLP 모델의 독보적 기능을 보여주는 명확한 예시들

# ============================================================================
# 예시 1: 만료된 인턴 계정 (6개월 전 만료)
# ============================================================================
resource "aws_iam_user" "expired_intern" {
  name = "summer-intern-2024"
  
  tags = {
    Type = "temporary"
    Role = "intern"
    StartDate = "2024-06-01"
    EndDate = "2024-08-31"  # ← 2024년 8월 31일에 만료됨!
    Manager = "john.doe@company.com"
    Team = "engineering"
  }
}

# 만료된 계정인데도 여전히 강력한 권한 보유
resource "aws_iam_user_policy_attachment" "expired_intern_access" {
  user       = aws_iam_user.expired_intern.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# ============================================================================
# 예시 2: 장기간 미사용 계정 (10개월 동안 미사용)
# ============================================================================
resource "aws_iam_user" "unused_service" {
  name = "legacy-api-service"
  
  tags = {
    Service = "legacy-api"
    LastUsed = "2024-01-15"  # ← 2024년 1월 15일 마지막 사용
    Purpose = "deprecated-api"
    Status = "to-be-removed"
  }
}

# 10개월 동안 사용 안 했는데 여전히 권한 보유
resource "aws_iam_user_policy" "unused_service_policy" {
  name = "legacy-api-permissions"
  user = aws_iam_user.unused_service.name
  
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
# 예시 3: 백업 서비스가 IAM 권한 보유 (목적 불일치)
# ============================================================================
resource "aws_iam_user" "backup_service" {
  name = "automated-backup-service"
  
  tags = {
    Service = "backup"
    Purpose = "database-backup"
    Critical = "true"
  }
}

# 백업 서비스인데 왜 IAM 권한이 필요한가?
resource "aws_iam_user_policy" "backup_with_iam" {
  name = "backup-service-policy"
  user = aws_iam_user.backup_service.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # 정상적인 백업 권한
        Effect = "Allow"
        Action = [
          "rds:CreateDBSnapshot",
          "s3:PutObject"
        ]
        Resource = "*"
      },
      {
        # 의심스러운 권한: 백업 서비스가 왜 IAM 권한을?
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:ListUsers",
          "iam:GetUser"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# 예시 4: 모니터링 서비스가 삭제 권한 보유 (목적 불일치)
# ============================================================================
resource "aws_iam_user" "monitoring_service" {
  name = "cloudwatch-monitoring"
  
  tags = {
    Service = "monitoring"
    Vendor = "datadog"
    Purpose = "metrics-collection"
  }
}

# 모니터링 서비스인데 왜 삭제 권한이?
resource "aws_iam_user_policy" "monitoring_with_delete" {
  name = "monitoring-permissions"
  user = aws_iam_user.monitoring_service.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # 정상적인 모니터링 권한 (읽기 전용)
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      },
      {
        # 의심스러운 권한: 모니터링이 왜 삭제 권한을?
        Effect = "Allow"
        Action = [
          "ec2:TerminateInstances",
          "rds:DeleteDBInstance",
          "s3:DeleteObject"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# 예시 5: 계약직 계정 만료 (3개월 전 만료)
# ============================================================================
resource "aws_iam_user" "contractor_expired" {
  name = "contractor-john-2024"
  
  tags = {
    Type = "contractor"
    Company = "ExternalConsulting Inc"
    StartDate = "2024-03-01"
    EndDate = "2024-07-31"  # ← 2024년 7월 31일 만료
    Project = "cloud-migration"
  }
}

# 계약 종료된 외부 업체 계정이 여전히 활성
resource "aws_iam_user_policy_attachment" "contractor_access" {
  user       = aws_iam_user.contractor_expired.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ============================================================================
# 예시 6: CI/CD 서비스의 과도한 권한 (목적 불일치)
# ============================================================================
resource "aws_iam_user" "cicd_service" {
  name = "github-actions-deploy"
  
  tags = {
    Service = "ci-cd"
    Purpose = "deployment"
    System = "github-actions"
  }
}

# CI/CD는 배포만 하면 되는데 관리자 권한?
resource "aws_iam_user_policy_attachment" "cicd_admin" {
  user       = aws_iam_user.cicd_service.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ============================================================================
# 예시 7: 임시 테스트 계정 (만료일 없음)
# ============================================================================
resource "aws_iam_user" "temp_test_account" {
  name = "temp-load-test-2024"
  
  tags = {
    Type = "temporary"
    Purpose = "load-testing"
    CreatedBy = "performance-team"
    # EndDate가 없음! ← 임시 계정인데 만료일이 없음
  }
}

# 임시 테스트 계정인데 만료일도 없고 강력한 권한
resource "aws_iam_user_policy_attachment" "temp_test_access" {
  user       = aws_iam_user.temp_test_account.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# ============================================================================
# 우리 NLP 모델이 탐지할 수 있는 위험들:
#
# 1. expired_intern: "2024년 8월 31일에 만료된 인턴 계정이 아직 활성화"
# 2. unused_service: "2024년 1월 15일 이후 10개월 동안 미사용"
# 3. backup_with_iam: "백업 서비스가 IAM 권한 보유 (목적 불일치)"
# 4. monitoring_with_delete: "모니터링 서비스가 삭제 권한 보유 (목적 불일치)"
# 5. contractor_expired: "2024년 7월 31일 계약 종료된 외부 업체 계정 활성"
# 6. cicd_admin: "CI/CD 서비스에 불필요한 관리자 권한"
# 7. temp_test_account: "임시 계정에 만료일 미설정"
#
# TFSec/Checkov는 이런 위험들을 절대 탐지할 수 없습니다!
# ============================================================================
# Multi-Hop Privilege Escalation Scenario
# 이 파일은 복잡한 다단계 권한 상승 공격 경로를 시뮬레이션합니다.
# 각 단계별로는 무해해 보이지만, 연결되면 심각한 보안 위험을 초래합니다.

# ============================================================================
# Step 1: 무해해 보이는 개발자 계정
# ==========================================================================
resource "aws_iam_user" "junior_developer" {
  name = "junior-dev-intern"
  
  tags = {
    Team        = "development"
    Level       = "junior"
    Temporary   = "true"
    Supervisor  = "senior.dev@company.com"
    StartDate   = "2024-01-15"
    # 만료일 없음 - 첫 번째 위험 신호
  }
}

# Step 1 권한: 겉보기에는 제한적인 Lambda 권한
resource "aws_iam_user_policy" "junior_dev_lambda" {
  name = "junior-lambda-basic"
  user = aws_iam_user.junior_developer.name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunction",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:lambda:*:*:function:dev-*",
          "arn:aws:logs:*:*:*"
        ]
      },
      {
        # 위험하지만 인식 안 됌: PassRole 권한
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = "arn:aws:iam::*:role/lambda-*"
        Condition = {
          StringEquals = {
            "iam:PassedToService": "lambda.amazonaws.com"
          }
        }
      }
    ]
  })
}

# ============================================================================
# Step 2: 중간 단계 - Lambda 실행 역할 (과도한 권한)
# ============================================================================
resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda-data-processor-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
      {
        # 위험: 사용자도 이 역할을 가정할 수 있음
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::*:user/*"
        }
        Condition = {
          StringLike = {
            "aws:userid": "*dev*"
          }
        }
      }
    ]
  })
  
  tags = {
    Purpose = "data processing"
    Service = "lambda"
  }
}

# Lambda 역할에 과도한 권한 부여
resource "aws_iam_role_policy" "lambda_data_access" {
  name = "lambda-data-processing-policy"
  role = aws_iam_role.lambda_execution_role.id
  
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
          "arn:aws:s3:::company-data-*/*",
          "arn:aws:s3:::company-data-*"
        ]
      },
      {
        # 위험한 권한: 다른 역할 가정 가능
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        Resource = "arn:aws:iam::*:role/service-*"
      },
      {
        # 위험한 권한: IAM 정보 조회
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:GetRole",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# Step 3: 최종 목표 - 높은 권한의 서비스 역할
# ============================================================================
resource "aws_iam_role" "service_admin_role" {
  name = "service-backup-automation"
  
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
        # 위험: Lambda 역할도 이 역할을 가정할 수 있음
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution_role.arn
        }
      }
    ]
  })
  
  tags = {
    Purpose = "automated backup"
    Critical = "true"
  }
}

# 최종 목표 역할에 관리자 권한
resource "aws_iam_role_policy_attachment" "service_admin_policy" {
  role       = aws_iam_role.service_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ============================================================================
# Step 4: 공격 경로를 숨기는 추가 리소스들
# ============================================================================

# 무해해 보이는 Lambda 함수
resource "aws_lambda_function" "data_processor" {
  filename         = "data_processor.zip"
  function_name    = "dev-data-processor"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  
  # 실제로는 권한 상승 코드가 포함될 수 있음
  
  tags = {
    Environment = "development"
    Purpose     = "data processing"
  }
}

# 로그 그룹 (공격 흔적 숨기기 용도)
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/dev-data-processor"
  retention_in_days = 1  # 짧은 보존 기간으로 증거 인멸
  
  tags = {
    Environment = "development"
  }
}

# ============================================================================
# Step 5: 추가적인 측면 공격 벡터
# ============================================================================

# 크로스 계정 역할 (외부 공격자 진입점)
resource "aws_iam_role" "cross_account_contractor" {
  name = "contractor-limited-access"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          # 외부 계정 (공격자가 제어할 수 있는 계정)
          AWS = "arn:aws:iam::123456789012:root"
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId": "contractor-2024"
          }
        }
      }
    ]
  })
  
  tags = {
    Type = "contractor"
    Company = "TrustedContractor Inc"
    Project = "data-migration"
  }
}

# 계약업체 역할에 겉보기 제한적 권한
resource "aws_iam_role_policy" "contractor_policy" {
  name = "contractor-data-access"
  role = aws_iam_role.cross_account_contractor.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject"
        ]
        Resource = [
          "arn:aws:s3:::migration-data/*",
          "arn:aws:s3:::migration-data"
        ]
      },
      {
        # 숨겨진 위험: Lambda 함수 실행 권한
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:*:*:function:dev-*"
      }
    ]
  })
}

# ============================================================================
# 공격 시나리오 요약:
# 
# 1. 공격자가 junior-dev-intern 계정 탈취
# 2. PassRole 권한으로 lambda-data-processor-role 역할 사용
# 3. Lambda 역할의 AssumeRole 권한으로 service-backup-automation 역할 가정
# 4. 최종적으로 AdministratorAccess 권한 획득
# 
# 또는:
# 1. 외부 공격자가 contractor-limited-access 역할 가정
# 2. Lambda 함수 실행 권한으로 dev-data-processor 함수 호출
# 3. Lambda 함수 내에서 권한 상승 코드 실행
# 4. 다단계 역할 가정을 통해 관리자 권한 획득
# ============================================================================
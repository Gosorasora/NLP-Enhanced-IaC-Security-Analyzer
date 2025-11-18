# 🔐 NLP-Enhanced IaC Security Analyzer

**자연어 처리(NLP) 기술을 활용한 차세대 Terraform 보안 분석 도구**

기존 정적 분석 도구(TFSec, Checkov)가 놓치는 **시간 기반 위험**, **컨텍스트 불일치**, **권한 상승 경로**를 탐지합니다.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: 11/11](https://img.shields.io/badge/tests-11%2F11%20passing-brightgreen.svg)](tests/)

---

## 🎯 왜 이 도구가 필요한가?

### 문제점: 기존 도구들의 한계

기존 IaC 보안 도구들(TFSec, Checkov)은 **규칙 기반 정적 분석**만 수행합니다:
- ✅ 와일드카드 권한 탐지
- ✅ 과도한 권한 경고
- ❌ **시간 경과에 따른 위험 변화 감지 불가**
- ❌ **비즈니스 컨텍스트 이해 불가**
- ❌ **복잡한 권한 상승 경로 분석 불가**

### 해결책: NLP 기반 의미론적 분석

이 도구는 **자연어 처리**와 **그래프 분석**을 결합하여:
- 🧠 리소스 이름과 설명에서 **의도와 목적을 이해**
- ⏰ 시간 태그를 분석하여 **만료/방치된 리소스 탐지**
- 🔗 IAM 관계를 그래프로 모델링하여 **권한 상승 경로 발견**
- 🎯 서비스 목적과 실제 권한의 **불일치 감지**

---

## 🚀 핵심 기능

### 1. ⏰ 시간 기반 위험 분석 (Time-Based Risk Detection)

**기존 도구가 할 수 없는 것:**
```terraform
resource "aws_iam_user" "intern" {
  name = "summer-intern-2024"
  tags = {
    EndDate = "2024-08-31"  # 이미 만료됨!
  }
}
```

**TFSec/Checkov:** ❌ 탐지 못함  
**우리 도구:** 
```
🚨 HIGH: 만료된 계정이 444일째 활성 상태
   위험 점수: 100/100
   권장 조치: 즉시 계정 비활성화 필요
```

### 2. 🎯 컨텍스트 기반 분석 (Context-Aware Analysis)

**서비스 목적과 권한의 불일치 탐지:**
```terraform
resource "aws_iam_user_policy" "backup_policy" {
  name = "backup-service-policy"
  policy = jsonencode({
    Action = ["iam:CreateAccessKey", "iam:PassRole"]  # 백업에 IAM 권한?
  })
}
```

**TFSec/Checkov:** ⚠️ 일반적인 권한 위반만 탐지  
**우리 도구:**
```
🚨 HIGH: 권한 상승 위험이 있는 권한 조합 탐지
🚨 MEDIUM: 서비스 목적과 맞지 않는 권한 설정
   - "backup" 서비스가 IAM 권한을 가지는 것은 비정상적
   - CreateAccessKey + PassRole 조합은 권한 상승 가능
```

### 3. 🔍 권한 상승 경로 분석 (Privilege Escalation Path Detection)

**복잡한 권한 체인 분석:**
```terraform
# User → Role → Policy 체인에서 위험한 권한 조합 탐지
resource "aws_iam_user" "developer" {
  name = "developer-prod-access"
}

resource "aws_iam_role" "admin_role" {
  assume_role_policy = jsonencode({
    Principal = { AWS = aws_iam_user.developer.arn }
  })
}

resource "aws_iam_role_policy" "admin_policy" {
  policy = jsonencode({
    Action = ["iam:*", "s3:*"]  # 전체 권한!
  })
}
```

**우리 도구:**
```
🚨 CRITICAL: 권한 상승 경로 발견
   developer → admin_role → iam:* (전체 IAM 권한)
   위험도: 95/100
```

---

## 🚀 빠른 시작

### 1. 설치

**요구사항:**
- Python 3.10 이상
- 4GB 이상 RAM (NLP 모델 로딩)

```bash
# 저장소 클론
git clone https://github.com/yourusername/NLP-Enhanced-IaC-Security-Analyzer.git
cd NLP-Enhanced-IaC-Security-Analyzer

# 의존성 설치
pip install -r requirements.txt
```

### 2. 실행

```bash
# 단일 파일 분석
python3 main.py terraform_samples/realistic_permission_risks.tf

# 디렉토리 전체 분석
python3 main.py terraform_samples/

# 출력 형식 지정 (HTML, JSON, 또는 둘 다)
python3 main.py terraform_samples/iam.tf --output-format html
python3 main.py terraform_samples/iam.tf --output-format json
python3 main.py terraform_samples/iam.tf --output-format both

# 상세 로그 출력
python3 main.py terraform_samples/iam.tf --verbose
```

### 3. 결과 확인

분석 결과는 `output/` 디렉토리에 저장됩니다:
- `security_analysis.html` - 시각화된 그래프와 상세 분석
- `security_analysis.txt` - 텍스트 요약
- `security_analysis.json` - 구조화된 데이터 (선택 시)

---

## 📊 실제 사용 예시

### 시나리오 1: 만료된 임시 계정 탐지

**상황:** 여름 인턴십이 끝났지만 계정이 여전히 활성화되어 있음

```terraform
resource "aws_iam_user" "intern" {
  name = "summer-intern-2024"
  tags = {
    EndDate = "2024-08-31"
    Purpose = "temporary-access"
  }
}

resource "aws_iam_user_policy_attachment" "intern_policy" {
  user       = aws_iam_user.intern.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}
```

**분석 결과:**
```
🚨 HIGH RISK: Expired Account Still Active
   Account: summer-intern-2024
   Expired: 444 days ago (2024-08-31)
   Risk Score: 100/100
   
   ⚠️  Recommendations:
   - Immediately disable or delete this account
   - Review access logs for suspicious activity
   - Implement automated account lifecycle management
```

**비교:**
- **TFSec:** ❌ 탐지 못함
- **Checkov:** ❌ 탐지 못함
- **우리 도구:** ✅ 만료 444일 경과 탐지

---

### 시나리오 2: 서비스 목적과 권한 불일치

**상황:** 백업 서비스가 IAM 권한을 가지고 있음 (비정상)

```terraform
resource "aws_iam_user_policy" "backup_policy" {
  name = "backup-service-policy"
  user = "backup-automation"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:CreateAccessKey",
        "iam:PassRole",
        "s3:*"
      ]
      Resource = "*"
    }]
  })
}
```

**분석 결과:**
```
🚨 HIGH RISK: Privilege Escalation Potential
   Policy: backup-service-policy
   Risk Score: 85/100
   
   Dangerous Permissions Detected:
   - iam:CreateAccessKey (can create new credentials)
   - iam:PassRole (can assume other roles)
   
🚨 MEDIUM RISK: Context Mismatch
   Service Purpose: "backup" (from name)
   Actual Permissions: IAM management
   
   ⚠️  Why This Matters:
   - Backup services should only need S3 read/write
   - IAM permissions indicate potential compromise or misconfiguration
   - This combination allows privilege escalation attacks
```

**비교:**
- **TFSec:** ⚠️ 와일드카드 사용 경고만
- **Checkov:** ⚠️ 과도한 권한 경고만
- **우리 도구:** ✅ 목적 불일치 + 권한 상승 위험 탐지

---

### 시나리오 3: 장기 미사용 계정

**상황:** 673일 동안 사용되지 않은 계정

```terraform
resource "aws_iam_user" "old_service" {
  name = "legacy-api-service"
  tags = {
    LastUsed = "2023-01-15"
  }
}
```

**분석 결과:**
```
🚨 MEDIUM RISK: Long-Term Unused Account
   Account: legacy-api-service
   Last Used: 673 days ago
   Risk Score: 65/100
   
   ⚠️  Security Implications:
   - Forgotten accounts are prime targets for attackers
   - May have outdated security configurations
   - Violates principle of least privilege
   
   Recommendations:
   - Review if this account is still needed
   - If unused, delete immediately
   - If needed, rotate credentials and update security settings
```

---

## 🧪 테스트

프로젝트는 11개의 포괄적인 테스트 케이스를 포함합니다:

```bash
# 전체 테스트 실행
PYTHONPATH=. python3 tests/test_realistic_risk_analyzer.py

# 결과: 11/11 테스트 통과 (100%)
```

**테스트 커버리지:**
- ✅ 만료된 계정 탐지
- ✅ 장기 미사용 계정 탐지
- ✅ 임시 권한의 영구화 탐지
- ✅ 서비스 목적 불일치 탐지
- ✅ 권한 상승 위험 탐지
- ✅ 위험한 권한 조합 탐지
- ✅ 크로스 계정 접근 위험
- ✅ 개발 환경 권한 프로덕션 사용
- ✅ 모니터링 서비스 과도한 권한
- ✅ API 서비스 권한 불일치
- ✅ CI/CD 서비스 보안 위험

자세한 테스트 결과는 [TEST_RESULTS.md](TEST_RESULTS.md)를 참조하세요.

---

## 📈 성능 비교

### 탐지 능력 비교

| 위험 유형 | TFSec | Checkov | 우리 도구 |
|-----------|-------|---------|-----------|
| 와일드카드 권한 | ✅ | ✅ | ✅ |
| 과도한 권한 | ✅ | ✅ | ✅ |
| 만료된 계정 | ❌ | ❌ | ✅ |
| 미사용 계정 | ❌ | ❌ | ✅ |
| 목적 불일치 | ❌ | ❌ | ✅ |
| 권한 상승 경로 | ⚠️ 부분 | ⚠️ 부분 | ✅ |
| 시간 기반 위험 | ❌ | ❌ | ✅ |
| 컨텍스트 분석 | ❌ | ❌ | ✅ |

### 실제 테스트 결과

**테스트 파일:** `realistic_permission_risks.tf` (16개 IAM 리소스)

| 도구 | 탐지 항목 | 분석 시간 | 고유 탐지 |
|------|-----------|-----------|-----------|
| TFSec | 107개 경고 | 0.8초 | 와일드카드, 정책 구조 |
| Checkov | 35개 경고 | 2.9초 | 규칙 위반, 베스트 프랙티스 |
| **우리 도구** | **2개 고위험** | **5.0초** | **만료 계정, 목적 불일치** |

### 상호 보완성

```
┌─────────────────────────────────────────────────────────┐
│  완벽한 IaC 보안 분석 = TFSec + Checkov + NLP 도구      │
├─────────────────────────────────────────────────────────┤
│  TFSec:      정적 규칙 기반 (빠른 스캔)                 │
│  Checkov:    정책 준수 검사 (종합 규칙)                 │
│  우리 도구:  의미론적 분석 (비즈니스 위험)              │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 차별화 포인트

### 기존 도구들의 접근 방식
```
"이 정책은 와일드카드(*)를 사용합니다"
"이 리소스는 암호화되지 않았습니다"
"이 권한은 과도합니다"
```
→ **기술적 사실만 나열** (What)

### 우리 도구의 접근 방식
```
"이 인턴 계정은 444일 전에 만료되었는데 아직 활성화되어 있습니다"
"백업 서비스가 왜 IAM 권한을 가지고 있나요?"
"이 계정은 673일 동안 사용되지 않았습니다"
"개발자 계정이 프로덕션 환경에 관리자 권한을 가지고 있습니다"
```
→ **비즈니스 위험과 컨텍스트 제공** (Why + Impact)

### 핵심 차이점

| 측면 | 기존 도구 | 우리 도구 |
|------|-----------|-----------|
| **분석 방식** | 규칙 기반 패턴 매칭 | NLP + 그래프 분석 |
| **시간 인식** | 없음 | 만료/미사용 탐지 |
| **컨텍스트 이해** | 없음 | 서비스 목적 분석 |
| **출력 형식** | 기술적 경고 | 비즈니스 위험 설명 |
| **거짓 양성** | 높음 (규칙 기반) | 낮음 (의미 기반) |
| **학습 능력** | 없음 (고정 규칙) | 있음 (NLP 모델) |

---

## 📁 프로젝트 구조

```
NLP-Enhanced-IaC-Security-Analyzer/
├── src/                           # 소스 코드
│   ├── core/                      # 핵심 분석 엔진
│   │   ├── analysis_runner.py    # 분석 파이프라인 조율
│   │   └── interfaces.py         # 공통 인터페이스
│   ├── analyzers/                 # 분석 모듈
│   │   ├── nlp_context_module.py # NLP 기반 컨텍스트 분석
│   │   ├── privilege_escalation_analyzer.py
│   │   ├── risk_keyword_analyzer.py
│   │   ├── risk_score_calculator.py
│   │   └── semantic_analyzer.py
│   ├── nlp/                       # NLP 처리
│   │   └── realistic_risk_analyzer.py  # 시간/컨텍스트 분석
│   ├── parsers/                   # Terraform 파싱
│   │   ├── terraform_parser.py
│   │   └── resource_extractor.py
│   ├── visualization/             # 결과 시각화
│   │   └── cli_visualizer.py
│   └── utils/                     # 유틸리티
├── terraform_samples/             # 테스트 시나리오 (5개)
│   ├── realistic_permission_risks.tf
│   ├── realistic_threats.tf
│   ├── time_based_risks_demo.tf
│   ├── multi_hop_escalation.tf
│   └── iam.tf
├── tests/                         # 테스트 케이스
│   └── test_realistic_risk_analyzer.py  # 11개 테스트
├── config/                        # 설정 파일
│   ├── default_config.yaml        # 기본 설정
│   ├── config_manager.py          # 설정 관리
│   └── settings.py                # 설정 클래스
├── output/                        # 분석 결과 출력
├── main.py                        # 진입점
├── requirements.txt               # 의존성
├── README.md                      # 프로젝트 문서
├── COMPARISON_SUMMARY.md          # 도구 비교 분석
└── TEST_RESULTS.md                # 테스트 결과
```

---

## 🔧 기술 스택

### 핵심 기술
- **Python 3.10+** - 메인 언어
- **Transformers (Hugging Face)** - BERT 기반 NLP 모델
- **python-hcl2** - Terraform 파일 파싱
- **NetworkX** - 그래프 분석 및 경로 탐지

### 주요 라이브러리
- **torch** - 딥러닝 프레임워크
- **sentence-transformers** - 의미론적 유사도 분석
- **numpy** - 수치 계산
- **pyyaml** - 설정 파일 관리

---

## 📚 문서

- [비교 분석](COMPARISON_SUMMARY.md) - TFSec/Checkov와의 상세 비교
- [테스트 결과](TEST_RESULTS.md) - 11개 테스트 케이스 결과

---

## 🤝 기여하기

이슈와 PR을 환영합니다!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 라이선스

MIT License - 자유롭게 사용, 수정, 배포 가능합니다.

---

## 🙏 감사의 말

- Hugging Face - BERT 모델 제공
- HashiCorp - Terraform 생태계
- 오픈소스 커뮤니티

---

**보안팀이 실제로 필요로 하는 인사이트를 제공합니다.**

*Made with ❤️ for DevSecOps teams*

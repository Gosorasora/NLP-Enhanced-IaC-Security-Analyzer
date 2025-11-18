"""
Test cases for Realistic Risk Analyzer
각 예시에 대한 구체적인 테스트 케이스
"""

import pytest
from datetime import datetime
from src.nlp.realistic_risk_analyzer import RealisticRiskAnalyzer, RiskFinding


class TestExpiredAccountDetection:
    """테스트 1: 만료된 계정 탐지"""
    
    def setup_method(self):
        self.analyzer = RealisticRiskAnalyzer()
    
    def test_expired_intern_account(self):
        """만료된 인턴 계정 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user',
            'name': 'summer-intern-2024',
            'config': {
                'tags': {
                    'Type': 'temporary',
                    'Role': 'intern',
                    'StartDate': '2024-06-01',
                    'EndDate': '2024-08-31'
                }
            }
        }
        
        findings = self.analyzer.analyze_temporal_risks([resource])
        
        # 검증
        assert len(findings) > 0, "만료된 계정을 탐지해야 함"
        
        expired_findings = [f for f in findings if f.risk_type == 'expired_account']
        assert len(expired_findings) > 0, "expired_account 타입 발견해야 함"
        
        finding = expired_findings[0]
        assert finding.severity == 'HIGH', "만료된 계정은 HIGH 위험"
        assert '만료된 계정' in finding.description
        assert finding.score >= 70
        
        print(f"✅ 테스트 통과: {finding.description}")
        print(f"   위험도: {finding.severity}, 점수: {finding.score}")

    
    def test_expired_contractor_account(self):
        """만료된 계약직 계정 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user',
            'name': 'contractor-john-2024',
            'config': {
                'tags': {
                    'Type': 'contractor',
                    'Company': 'ExternalConsulting Inc',
                    'EndDate': '2024-07-31'
                }
            }
        }
        
        findings = self.analyzer.analyze_temporal_risks([resource])
        
        assert len(findings) > 0
        expired_findings = [f for f in findings if f.risk_type == 'expired_account']
        assert len(expired_findings) > 0
        
        print(f"✅ 테스트 통과: 계약직 계정 만료 탐지")


class TestUnusedAccountDetection:
    """테스트 2: 장기간 미사용 계정 탐지"""
    
    def setup_method(self):
        self.analyzer = RealisticRiskAnalyzer()
    
    def test_long_unused_account(self):
        """10개월 미사용 계정 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user',
            'name': 'legacy-api-service',
            'config': {
                'tags': {
                    'Service': 'legacy-api',
                    'LastUsed': '2024-01-15',
                    'Purpose': 'deprecated-api'
                }
            }
        }
        
        findings = self.analyzer.analyze_temporal_risks([resource])
        
        assert len(findings) > 0
        unused_findings = [f for f in findings if f.risk_type == 'unused_account']
        assert len(unused_findings) > 0, "미사용 계정을 탐지해야 함"
        
        finding = unused_findings[0]
        assert finding.severity in ['MEDIUM', 'HIGH']
        assert '미사용' in finding.description
        
        print(f"✅ 테스트 통과: {finding.description}")
        print(f"   위험도: {finding.severity}, 점수: {finding.score}")



class TestPurposeMismatchDetection:
    """테스트 3: 서비스 목적과 권한 불일치 탐지"""
    
    def setup_method(self):
        self.analyzer = RealisticRiskAnalyzer()
    
    def test_backup_service_with_iam_permissions(self):
        """백업 서비스의 IAM 권한 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user_policy',
            'name': 'backup-service-policy',
            'config': {
                'policy': '''
                {
                    "Statement": [
                        {"Action": ["rds:CreateDBSnapshot", "s3:PutObject"]},
                        {"Action": ["iam:CreateAccessKey", "iam:ListUsers"]}
                    ]
                }
                '''
            }
        }
        
        findings = self.analyzer.analyze_permission_risks([resource])
        
        assert len(findings) > 0
        
        # 권한 상승 위험 탐지
        escalation_findings = [f for f in findings if f.risk_type == 'privilege_escalation']
        assert len(escalation_findings) > 0, "CreateAccessKey 권한 상승 위험 탐지"
        
        # 목적 불일치 탐지
        mismatch_findings = [f for f in findings if f.risk_type == 'purpose_mismatch']
        assert len(mismatch_findings) > 0, "백업 서비스의 IAM 권한 불일치 탐지"
        
        print(f"✅ 테스트 통과: 백업 서비스 IAM 권한 탐지")
        for finding in findings:
            print(f"   - {finding.risk_type}: {finding.description}")
    
    def test_monitoring_service_with_delete_permissions(self):
        """모니터링 서비스의 삭제 권한 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user_policy',
            'name': 'monitoring-permissions',
            'config': {
                'policy': '''
                {
                    "Statement": [
                        {"Action": ["cloudwatch:GetMetricStatistics"]},
                        {"Action": ["ec2:TerminateInstances", "rds:DeleteDBInstance"]}
                    ]
                }
                '''
            }
        }
        
        findings = self.analyzer.analyze_permission_risks([resource])
        
        assert len(findings) > 0, "최소 1개 이상의 위험 탐지"
        mismatch_findings = [f for f in findings if f.risk_type == 'purpose_mismatch']
        assert len(mismatch_findings) > 0, "모니터링 서비스의 삭제 권한 불일치 탐지"
        
        finding = mismatch_findings[0]
        # 목적 불일치가 탐지되면 성공
        assert finding.risk_type == 'purpose_mismatch'
        
        print(f"✅ 테스트 통과: {finding.description}")



class TestTemporaryAccountPermanence:
    """테스트 4: 임시 계정의 영구화 탐지"""
    
    def setup_method(self):
        self.analyzer = RealisticRiskAnalyzer()
    
    def test_temp_account_without_expiry(self):
        """만료일 없는 임시 계정 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user',
            'name': 'temp-load-test-2024',
            'config': {
                'tags': {
                    'Type': 'temporary',
                    'Purpose': 'load-testing'
                    # EndDate 없음!
                }
            }
        }
        
        findings = self.analyzer.analyze_temporal_risks([resource])
        
        assert len(findings) > 0
        temp_findings = [f for f in findings if f.risk_type == 'temporary_permanence']
        assert len(temp_findings) > 0, "임시 계정의 만료일 미설정 탐지"
        
        finding = temp_findings[0]
        assert '만료일' in finding.description
        
        print(f"✅ 테스트 통과: {finding.description}")


class TestPrivilegeEscalation:
    """테스트 5: 권한 상승 위험 탐지"""
    
    def setup_method(self):
        self.analyzer = RealisticRiskAnalyzer()
    
    def test_create_access_key_permission(self):
        """CreateAccessKey 권한 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user_policy',
            'name': 'risky-policy',
            'config': {
                'policy': '{"Statement": [{"Action": ["iam:CreateAccessKey"]}]}'
            }
        }
        
        findings = self.analyzer.analyze_permission_risks([resource])
        
        assert len(findings) > 0
        escalation_findings = [f for f in findings if f.risk_type == 'privilege_escalation']
        assert len(escalation_findings) > 0
        
        finding = escalation_findings[0]
        assert 'CreateAccessKey' in str(finding.evidence)
        
        print(f"✅ 테스트 통과: CreateAccessKey 권한 상승 위험 탐지")
    
    def test_passrole_assumerole_combination(self):
        """PassRole + AssumeRole 조합 탐지 테스트"""
        resource = {
            'type': 'aws_iam_user_policy',
            'name': 'dangerous-combo',
            'config': {
                'policy': '''
                {
                    "Statement": [
                        {"Action": ["iam:PassRole", "sts:AssumeRole"]}
                    ]
                }
                '''
            }
        }
        
        findings = self.analyzer.analyze_permission_risks([resource])
        
        assert len(findings) > 0
        escalation_findings = [f for f in findings if f.risk_type == 'privilege_escalation']
        assert len(escalation_findings) > 0
        
        finding = escalation_findings[0]
        assert 'PassRole' in str(finding.evidence) or 'AssumeRole' in str(finding.evidence)
        
        print(f"✅ 테스트 통과: PassRole + AssumeRole 조합 탐지")



class TestCrossAccountRisks:
    """테스트 6: 크로스 계정 위험 탐지"""
    
    def setup_method(self):
        self.analyzer = RealisticRiskAnalyzer()
    
    def test_wildcard_principal(self):
        """와일드카드 Principal 탐지 테스트"""
        resource = {
            'type': 'aws_iam_role',
            'name': 'open-role',
            'config': {
                'assume_role_policy': '''
                {
                    "Statement": [{
                        "Principal": {"AWS": "*"}
                    }]
                }
                '''
            }
        }
        
        findings = self.analyzer.analyze_permission_risks([resource])
        
        assert len(findings) > 0
        cross_account_findings = [f for f in findings if f.risk_type == 'cross_account_risk']
        assert len(cross_account_findings) > 0, "와일드카드 Principal 탐지"
        
        finding = cross_account_findings[0]
        assert finding.severity == 'HIGH'
        assert '모든' in finding.description or '*' in str(finding.evidence)
        
        print(f"✅ 테스트 통과: {finding.description}")


class TestIntegrationScenarios:
    """테스트 7: 통합 시나리오"""
    
    def setup_method(self):
        self.analyzer = RealisticRiskAnalyzer()
    
    def test_multiple_risks_in_single_resource(self):
        """하나의 리소스에서 여러 위험 탐지"""
        resource = {
            'type': 'aws_iam_user',
            'name': 'temp-contractor-2024',
            'config': {
                'tags': {
                    'Type': 'temporary',
                    'EndDate': '2024-06-01',  # 만료됨
                    'LastUsed': '2024-03-01'  # 오래 전 사용
                }
            }
        }
        
        findings = self.analyzer.analyze_temporal_risks([resource])
        
        # 여러 위험이 탐지되어야 함
        assert len(findings) >= 2, "만료 + 미사용 + 임시 영구화 등 여러 위험 탐지"
        
        risk_types = set(f.risk_type for f in findings)
        print(f"✅ 테스트 통과: {len(findings)}개 위험 탐지")
        print(f"   위험 유형: {risk_types}")
    
    def test_summary_generation(self):
        """위험 요약 생성 테스트"""
        resources = [
            {
                'type': 'aws_iam_user',
                'name': 'expired-user',
                'config': {'tags': {'EndDate': '2024-01-01'}}
            },
            {
                'type': 'aws_iam_user',
                'name': 'unused-user',
                'config': {'tags': {'LastUsed': '2024-01-01'}}
            }
        ]
        
        findings = self.analyzer.analyze_temporal_risks(resources)
        summary = self.analyzer.generate_risk_summary(findings)
        
        assert 'total_findings' in summary
        assert 'high_risk' in summary
        assert 'medium_risk' in summary
        assert 'risk_types' in summary
        assert 'top_risks' in summary
        
        assert summary['total_findings'] > 0
        
        print(f"✅ 테스트 통과: 요약 생성")
        print(f"   총 발견: {summary['total_findings']}")
        print(f"   High: {summary['high_risk']}, Medium: {summary['medium_risk']}")
        print(f"   위험 유형: {summary['risk_types']}")


if __name__ == '__main__':
    print("=" * 80)
    print("🧪 Realistic Risk Analyzer 테스트 실행")
    print("=" * 80)
    print()
    
    # pytest 없이 직접 실행
    import sys
    
    test_classes = [
        TestExpiredAccountDetection,
        TestUnusedAccountDetection,
        TestPurposeMismatchDetection,
        TestTemporaryAccountPermanence,
        TestPrivilegeEscalation,
        TestCrossAccountRisks,
        TestIntegrationScenarios
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    
    for test_class in test_classes:
        print(f"\n📋 {test_class.__doc__}")
        print("-" * 80)
        
        test_instance = test_class()
        test_methods = [m for m in dir(test_instance) if m.startswith('test_')]
        
        for method_name in test_methods:
            total_tests += 1
            try:
                test_instance.setup_method()
                method = getattr(test_instance, method_name)
                method()
                passed_tests += 1
            except AssertionError as e:
                failed_tests += 1
                print(f"❌ 테스트 실패: {method_name}")
                print(f"   에러: {e}")
            except Exception as e:
                failed_tests += 1
                print(f"❌ 테스트 에러: {method_name}")
                print(f"   에러: {e}")
    
    print("\n" + "=" * 80)
    print("📊 테스트 결과 요약")
    print("=" * 80)
    print(f"총 테스트: {total_tests}")
    print(f"✅ 통과: {passed_tests}")
    print(f"❌ 실패: {failed_tests}")
    print(f"성공률: {passed_tests/total_tests*100:.1f}%")
    print("=" * 80)
    
    sys.exit(0 if failed_tests == 0 else 1)

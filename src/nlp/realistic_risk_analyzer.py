"""
Realistic Risk Analyzer
실제 권한 설정과 시간 패턴 기반 위험 분석
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass

@dataclass
class RiskFinding:
    resource_name: str
    risk_type: str
    severity: str
    description: str
    evidence: List[str]
    score: int

class RealisticRiskAnalyzer:
    def __init__(self):
        self.current_date = datetime.now()
        
        # 실제 위험 패턴들
        self.permission_risks = {
            'privilege_escalation': {
                'patterns': ['iam:CreateAccessKey', 'iam:PassRole', 'sts:AssumeRole'],
                'severity': 'HIGH',
                'score': 80
            },
            'admin_access_overuse': {
                'patterns': ['AdministratorAccess', 'PowerUserAccess'],
                'severity': 'HIGH',
                'score': 70
            },
            'destructive_permissions': {
                'patterns': ['Delete', 'Terminate', 'Remove'],
                'severity': 'MEDIUM',
                'score': 60
            },
            'cross_account_risks': {
                'patterns': ['Principal.*\\*', 'AWS.*\\*'],
                'severity': 'HIGH',
                'score': 75
            }
        }
        
        # 서비스별 적절한 권한 매핑
        self.service_permission_map = {
            'ci': ['s3:PutObject', 'ecr:BatchCheckLayerAvailability', 'ecs:UpdateService'],
            'backup': ['s3:PutObject', 'rds:CreateDBSnapshot', 'ec2:CreateSnapshot'],
            'monitoring': ['cloudwatch:GetMetricStatistics', 'ec2:Describe*', 'rds:Describe*'],
            'lambda': ['logs:CreateLogGroup', 's3:GetObject', 'dynamodb:Query']
        }

    def analyze_permission_risks(self, resources: List[Dict]) -> List[RiskFinding]:
        """실제 권한 설정의 위험성 분석"""
        findings = []
        
        for resource in resources:
            # 1. 권한 과다 할당 분석
            findings.extend(self._analyze_privilege_escalation(resource))
            
            # 2. 목적과 권한 불일치 분석
            findings.extend(self._analyze_purpose_mismatch(resource))
            
            # 3. 환경 분리 실패 분석
            findings.extend(self._analyze_environment_isolation(resource))
            
            # 4. 크로스 계정 위험 분석
            findings.extend(self._analyze_cross_account_risks(resource))
        
        return findings

    def analyze_temporal_risks(self, resources: List[Dict]) -> List[RiskFinding]:
        """시간과 사용 패턴 기반 위험 분석"""
        findings = []
        
        for resource in resources:
            # 1. 만료된 계정 분석
            findings.extend(self._analyze_expired_accounts(resource))
            
            # 2. 장기간 미사용 계정 분석
            findings.extend(self._analyze_unused_accounts(resource))
            
            # 3. 임시 계정의 영구화 분석
            findings.extend(self._analyze_temporary_permanence(resource))
        
        return findings

    def _analyze_privilege_escalation(self, resource: Dict) -> List[RiskFinding]:
        """권한 상승 위험 분석"""
        findings = []
        
        if resource.get('type') not in ['aws_iam_user_policy', 'aws_iam_role_policy']:
            return findings
        
        policy_content = str(resource.get('config', {}))
        dangerous_permissions = []
        
        # 위험한 권한 조합 탐지
        if 'iam:CreateAccessKey' in policy_content:
            dangerous_permissions.append('iam:CreateAccessKey (새로운 액세스 키 생성 가능)')
        
        if 'iam:PassRole' in policy_content and 'sts:AssumeRole' in policy_content:
            dangerous_permissions.append('iam:PassRole + sts:AssumeRole (권한 상승 경로)')
        
        if 'AdministratorAccess' in policy_content:
            # 서비스 유형별로 필요성 판단
            service_type = self._identify_service_type(resource.get('name', ''))
            if service_type and service_type != 'admin':
                dangerous_permissions.append(f'{service_type} 서비스에 불필요한 관리자 권한')
        
        if dangerous_permissions:
            findings.append(RiskFinding(
                resource_name=resource.get('name', 'unknown'),
                risk_type='privilege_escalation',
                severity='HIGH',
                description='권한 상승 위험이 있는 권한 조합 탐지',
                evidence=dangerous_permissions,
                score=80
            ))
        
        return findings

    def _analyze_purpose_mismatch(self, resource: Dict) -> List[RiskFinding]:
        """목적과 권한 불일치 분석"""
        findings = []
        
        resource_name = resource.get('name', '').lower()
        policy_content = str(resource.get('config', {}))
        
        # 서비스 유형 식별
        service_type = self._identify_service_type(resource_name)
        if not service_type:
            return findings
        
        # 해당 서비스에 적절한 권한인지 확인
        appropriate_permissions = self.service_permission_map.get(service_type, [])
        inappropriate_permissions = []
        
        if service_type == 'backup':
            if 'iam:' in policy_content:
                inappropriate_permissions.append('백업 서비스에 IAM 권한')
            if 'Delete' in policy_content or 'Terminate' in policy_content:
                inappropriate_permissions.append('백업 서비스에 삭제 권한')
        
        elif service_type == 'monitoring':
            if any(action in policy_content for action in ['Delete', 'Terminate', 'Create', 'Put']):
                inappropriate_permissions.append('모니터링 서비스에 쓰기/삭제 권한')
        
        elif service_type == 'ci':
            if 'AdministratorAccess' in policy_content:
                inappropriate_permissions.append('CI/CD 서비스에 과도한 관리자 권한')
        
        if inappropriate_permissions:
            findings.append(RiskFinding(
                resource_name=resource.get('name', 'unknown'),
                risk_type='purpose_mismatch',
                severity='MEDIUM',
                description='서비스 목적과 맞지 않는 권한 설정',
                evidence=inappropriate_permissions,
                score=60
            ))
        
        return findings

    def _analyze_expired_accounts(self, resource: Dict) -> List[RiskFinding]:
        """만료된 계정 분석"""
        findings = []
        
        tags = resource.get('config', {}).get('tags', {})
        end_date_str = tags.get('EndDate') or tags.get('end_date')
        
        if end_date_str:
            try:
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                if end_date < self.current_date:
                    days_expired = (self.current_date - end_date).days
                    
                    findings.append(RiskFinding(
                        resource_name=resource.get('name', 'unknown'),
                        risk_type='expired_account',
                        severity='HIGH' if days_expired > 30 else 'MEDIUM',
                        description=f'만료된 계정이 {days_expired}일째 활성 상태',
                        evidence=[f'만료일: {end_date_str}', f'현재일: {self.current_date.strftime("%Y-%m-%d")}'],
                        score=70 + min(days_expired, 30)
                    ))
            except ValueError:
                pass  # 날짜 형식이 잘못된 경우 무시
        
        return findings

    def _analyze_unused_accounts(self, resource: Dict) -> List[RiskFinding]:
        """장기간 미사용 계정 분석"""
        findings = []
        
        tags = resource.get('config', {}).get('tags', {})
        last_used_str = tags.get('LastUsed') or tags.get('last_used')
        
        if last_used_str:
            try:
                last_used = datetime.strptime(last_used_str, '%Y-%m-%d')
                days_unused = (self.current_date - last_used).days
                
                if days_unused > 90:  # 3개월 이상 미사용
                    findings.append(RiskFinding(
                        resource_name=resource.get('name', 'unknown'),
                        risk_type='unused_account',
                        severity='MEDIUM' if days_unused < 365 else 'HIGH',
                        description=f'{days_unused}일 동안 미사용 계정',
                        evidence=[f'마지막 사용: {last_used_str}', f'미사용 기간: {days_unused}일'],
                        score=40 + min(days_unused // 30, 40)
                    ))
            except ValueError:
                pass
        
        return findings

    def _analyze_temporary_permanence(self, resource: Dict) -> List[RiskFinding]:
        """임시 계정의 영구화 분석"""
        findings = []
        
        resource_name = resource.get('name', '').lower()
        tags = resource.get('config', {}).get('tags', {})
        
        # 임시성을 나타내는 키워드들
        temp_indicators = ['temp', 'temporary', 'intern', 'contractor', 'demo', 'test']
        
        if any(indicator in resource_name for indicator in temp_indicators):
            # 임시 계정인데 만료일이 없거나 이미 지났는지 확인
            end_date_str = tags.get('EndDate') or tags.get('end_date')
            
            if not end_date_str:
                findings.append(RiskFinding(
                    resource_name=resource.get('name', 'unknown'),
                    risk_type='temporary_permanence',
                    severity='MEDIUM',
                    description='임시 계정에 만료일이 설정되지 않음',
                    evidence=[f'임시성 키워드: {[ind for ind in temp_indicators if ind in resource_name]}'],
                    score=50
                ))
            else:
                try:
                    end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                    if end_date < self.current_date:
                        days_expired = (self.current_date - end_date).days
                        findings.append(RiskFinding(
                            resource_name=resource.get('name', 'unknown'),
                            risk_type='temporary_permanence',
                            severity='HIGH',
                            description=f'임시 계정이 만료 후 {days_expired}일째 방치됨',
                            evidence=[f'만료일: {end_date_str}', f'계정 유형: 임시'],
                            score=60 + min(days_expired, 30)
                        ))
                except ValueError:
                    pass
        
        return findings

    def _identify_service_type(self, resource_name: str) -> str:
        """리소스 이름으로부터 서비스 유형 식별"""
        name_lower = resource_name.lower()
        
        if any(keyword in name_lower for keyword in ['jenkins', 'ci', 'cd', 'build', 'deploy']):
            return 'ci'
        elif any(keyword in name_lower for keyword in ['backup', 'snapshot']):
            return 'backup'
        elif any(keyword in name_lower for keyword in ['monitor', 'datadog', 'cloudwatch', 'metric']):
            return 'monitoring'
        elif any(keyword in name_lower for keyword in ['lambda', 'function']):
            return 'lambda'
        elif any(keyword in name_lower for keyword in ['admin', 'root', 'super']):
            return 'admin'
        
        return None

    def _analyze_cross_account_risks(self, resource: Dict) -> List[RiskFinding]:
        """크로스 계정 위험 분석"""
        findings = []
        
        if resource.get('type') != 'aws_iam_role':
            return findings
        
        assume_role_policy = str(resource.get('config', {}).get('assume_role_policy', ''))
        
        # 와일드카드 Principal 탐지
        if '"AWS": "*"' in assume_role_policy or '"AWS":"*"' in assume_role_policy:
            findings.append(RiskFinding(
                resource_name=resource.get('name', 'unknown'),
                risk_type='cross_account_risk',
                severity='HIGH',
                description='모든 AWS 계정이 이 역할을 가정할 수 있음',
                evidence=['Principal: "*" 설정 탐지'],
                score=85
            ))
        
        # 외부 계정 ID 패턴 분석
        external_account_pattern = r'"AWS":\s*"arn:aws:iam::(\d{12}):root"'
        matches = re.findall(external_account_pattern, assume_role_policy)
        
        if matches:
            findings.append(RiskFinding(
                resource_name=resource.get('name', 'unknown'),
                risk_type='cross_account_access',
                severity='MEDIUM',
                description='외부 AWS 계정의 역할 가정 허용',
                evidence=[f'외부 계정 ID: {account_id}' for account_id in matches],
                score=55
            ))
        
        return findings

    def generate_risk_summary(self, findings: List[RiskFinding]) -> Dict[str, Any]:
        """위험 분석 결과 요약"""
        summary = {
            'total_findings': len(findings),
            'high_risk': len([f for f in findings if f.severity == 'HIGH']),
            'medium_risk': len([f for f in findings if f.severity == 'MEDIUM']),
            'low_risk': len([f for f in findings if f.severity == 'LOW']),
            'risk_types': {},
            'top_risks': sorted(findings, key=lambda x: x.score, reverse=True)[:5]
        }
        
        # 위험 유형별 집계
        for finding in findings:
            risk_type = finding.risk_type
            if risk_type not in summary['risk_types']:
                summary['risk_types'][risk_type] = 0
            summary['risk_types'][risk_type] += 1
        
        return summary

    def _analyze_environment_isolation(self, resource: Dict) -> List[RiskFinding]:
        """환경 분리 실패 분석"""
        findings = []
        
        resource_name = resource.get('name', '').lower()
        policy_content = str(resource.get('config', {}))
        
        # 개발자 계정이 프로덕션 접근 권한을 가지는지 확인
        if any(keyword in resource_name for keyword in ['dev', 'developer', 'test']):
            if any(keyword in policy_content.lower() for keyword in ['prod', 'production']):
                findings.append(RiskFinding(
                    resource_name=resource.get('name', 'unknown'),
                    risk_type='environment_isolation',
                    severity='HIGH',
                    description='개발 계정이 프로덕션 환경 접근 권한 보유',
                    evidence=['개발 계정', '프로덕션 접근 권한'],
                    score=75
                ))
        
        return findings

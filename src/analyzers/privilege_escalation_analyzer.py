"""
Privilege Escalation Path Analyzer
NLP를 활용한 권한 상승 경로 탐지 및 분석
"""

import logging
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
import networkx as nx

@dataclass
class EscalationPath:
    """권한 상승 경로를 나타내는 데이터 클래스"""
    start_resource: str
    end_resource: str
    path: List[str]
    risk_score: float
    escalation_type: str
    description: str
    evidence: List[str]

class PrivilegeEscalationAnalyzer:
    """
    권한 상승 경로 탐지 및 분석기
    NLP를 사용하여 권한의 의미를 이해하고 위험한 경로를 탐지
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 권한 상승 가능한 IAM 액션들
        self.escalation_actions = {
            # 사용자/역할 생성 및 수정
            'iam:CreateUser': {'risk': 80, 'category': 'identity_creation'},
            'iam:CreateRole': {'risk': 80, 'category': 'identity_creation'},
            'iam:CreateAccessKey': {'risk': 90, 'category': 'credential_creation'},
            'iam:UpdateLoginProfile': {'risk': 85, 'category': 'credential_modification'},
            
            # 정책 연결 및 수정
            'iam:AttachUserPolicy': {'risk': 85, 'category': 'policy_attachment'},
            'iam:AttachRolePolicy': {'risk': 85, 'category': 'policy_attachment'},
            'iam:PutUserPolicy': {'risk': 85, 'category': 'policy_attachment'},
            'iam:PutRolePolicy': {'risk': 85, 'category': 'policy_attachment'},
            'iam:AttachGroupPolicy': {'risk': 80, 'category': 'policy_attachment'},
            'iam:PutGroupPolicy': {'risk': 80, 'category': 'policy_attachment'},
            
            # 정책 버전 관리
            'iam:CreatePolicyVersion': {'risk': 90, 'category': 'policy_modification'},
            'iam:SetDefaultPolicyVersion': {'risk': 90, 'category': 'policy_modification'},
            
            # 역할 가정 및 전달
            'sts:AssumeRole': {'risk': 75, 'category': 'role_assumption'},
            'iam:PassRole': {'risk': 85, 'category': 'role_passing'},
            
            # 신뢰 관계 수정
            'iam:UpdateAssumeRolePolicy': {'risk': 95, 'category': 'trust_modification'},
            
            # 그룹 관리
            'iam:AddUserToGroup': {'risk': 70, 'category': 'group_management'},
        }
        
        # 위험한 권한 조합 (함께 있으면 권한 상승 가능)
        self.dangerous_combinations = [
            {
                'actions': {'iam:PassRole', 'lambda:CreateFunction'},
                'risk': 95,
                'description': 'Lambda 함수 생성 + PassRole로 권한 상승 가능'
            },
            {
                'actions': {'iam:PassRole', 'ec2:RunInstances'},
                'risk': 90,
                'description': 'EC2 인스턴스 실행 + PassRole로 권한 상승 가능'
            },
            {
                'actions': {'iam:PassRole', 'sts:AssumeRole'},
                'risk': 95,
                'description': 'PassRole + AssumeRole 조합으로 권한 상승 가능'
            },
            {
                'actions': {'iam:CreateAccessKey', 'iam:ListUsers'},
                'risk': 85,
                'description': '다른 사용자의 액세스 키 생성 가능'
            },
            {
                'actions': {'iam:AttachUserPolicy', 'iam:CreatePolicy'},
                'risk': 90,
                'description': '정책 생성 후 사용자에게 연결 가능'
            },
            {
                'actions': {'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion'},
                'risk': 95,
                'description': '정책 버전 조작으로 권한 상승 가능'
            },
            {
                'actions': {'iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'},
                'risk': 95,
                'description': '신뢰 관계 수정 후 역할 가정 가능'
            }
        ]
        
        # 권한 상승 그래프
        self.escalation_graph = nx.DiGraph()
        
    def analyze_escalation_paths(self, resources: List[Dict]) -> List[EscalationPath]:
        """
        리소스들을 분석하여 권한 상승 경로를 탐지
        
        Args:
            resources: IAM 리소스 리스트
            
        Returns:
            탐지된 권한 상승 경로 리스트
        """
        self.logger.info(f"Analyzing {len(resources)} resources for escalation paths")
        
        # 그래프 구축
        self._build_escalation_graph(resources)
        
        # 권한 상승 경로 탐지
        paths = []
        
        # 1. 직접적인 권한 상승 액션 탐지
        paths.extend(self._detect_direct_escalation(resources))
        
        # 2. 위험한 권한 조합 탐지
        paths.extend(self._detect_dangerous_combinations(resources))
        
        # 3. 다단계 권한 상승 경로 탐지
        paths.extend(self._detect_multi_hop_escalation(resources))
        
        # 4. 역할 체인 분석
        paths.extend(self._analyze_role_chains(resources))
        
        self.logger.info(f"Found {len(paths)} potential escalation paths")
        
        return sorted(paths, key=lambda x: x.risk_score, reverse=True)
    
    def _build_escalation_graph(self, resources: List[Dict]):
        """권한 관계 그래프 구축"""
        self.escalation_graph.clear()
        
        for resource in resources:
            resource_type = resource.get('type', '')
            resource_name = resource.get('name', '')
            
            # 노드 추가
            self.escalation_graph.add_node(resource_name, **resource)
            
            # 관계 추가
            if resource_type == 'aws_iam_user_policy_attachment':
                user = resource.get('config', {}).get('user', '')
                if user:
                    self.escalation_graph.add_edge(user, resource_name, relation='has_policy')
            
            elif resource_type == 'aws_iam_role_policy_attachment':
                role = resource.get('config', {}).get('role', '')
                if role:
                    self.escalation_graph.add_edge(role, resource_name, relation='has_policy')
            
            elif resource_type == 'aws_iam_role':
                # AssumeRole 관계 분석
                assume_policy = str(resource.get('config', {}).get('assume_role_policy', ''))
                # Principal 분석하여 누가 이 역할을 가정할 수 있는지 파악
                # 간단한 구현: AWS 계정 ARN 추출
                import re
                principals = re.findall(r'"AWS":\s*"([^"]+)"', assume_policy)
                for principal in principals:
                    self.escalation_graph.add_edge(principal, resource_name, relation='can_assume')
    
    def _detect_direct_escalation(self, resources: List[Dict]) -> List[EscalationPath]:
        """직접적인 권한 상승 액션 탐지"""
        paths = []
        
        for resource in resources:
            if resource.get('type') not in ['aws_iam_user_policy', 'aws_iam_role_policy']:
                continue
            
            policy_content = str(resource.get('config', {}))
            resource_name = resource.get('name', '')
            
            # 권한 상승 액션 탐지
            found_actions = []
            for action, info in self.escalation_actions.items():
                if action in policy_content:
                    found_actions.append((action, info))
            
            if found_actions:
                # 가장 위험한 액션 기준으로 위험도 계산
                max_risk = max(info['risk'] for _, info in found_actions)
                
                path = EscalationPath(
                    start_resource=resource_name,
                    end_resource=resource_name,
                    path=[resource_name],
                    risk_score=max_risk,
                    escalation_type='direct_escalation',
                    description=f'권한 상승 가능한 IAM 액션 포함',
                    evidence=[f'{action} (위험도: {info["risk"]})' for action, info in found_actions]
                )
                paths.append(path)
        
        return paths
    
    def _detect_dangerous_combinations(self, resources: List[Dict]) -> List[EscalationPath]:
        """위험한 권한 조합 탐지"""
        paths = []
        
        for resource in resources:
            if resource.get('type') not in ['aws_iam_user_policy', 'aws_iam_role_policy']:
                continue
            
            policy_content = str(resource.get('config', {}))
            resource_name = resource.get('name', '')
            
            # 정책에 포함된 모든 액션 추출
            actions_in_policy = set()
            for action in self.escalation_actions.keys():
                if action in policy_content:
                    actions_in_policy.add(action)
            
            # 추가 액션들도 체크 (Lambda, EC2 등)
            import re
            all_actions = re.findall(r'"([a-z0-9]+:[A-Za-z*]+)"', policy_content)
            actions_in_policy.update(all_actions)
            
            # 위험한 조합 체크
            for combination in self.dangerous_combinations:
                required_actions = combination['actions']
                if required_actions.issubset(actions_in_policy):
                    path = EscalationPath(
                        start_resource=resource_name,
                        end_resource=resource_name,
                        path=[resource_name],
                        risk_score=combination['risk'],
                        escalation_type='dangerous_combination',
                        description=combination['description'],
                        evidence=[f'발견된 액션: {", ".join(required_actions)}']
                    )
                    paths.append(path)
        
        return paths
    
    def _detect_multi_hop_escalation(self, resources: List[Dict]) -> List[EscalationPath]:
        """다단계 권한 상승 경로 탐지"""
        paths = []
        
        # 사용자 → 역할 → 관리자 권한 경로 탐지
        users = [r for r in resources if r.get('type') == 'aws_iam_user']
        roles = [r for r in resources if r.get('type') == 'aws_iam_role']
        
        for user in users:
            user_name = user.get('name', '')
            
            # 사용자가 가정할 수 있는 역할 찾기
            for role in roles:
                role_name = role.get('name', '')
                assume_policy = str(role.get('config', {}).get('assume_role_policy', ''))
                
                # 사용자가 이 역할을 가정할 수 있는지 확인
                if user_name in assume_policy or '"AWS": "*"' in assume_policy:
                    # 역할이 위험한 권한을 가지고 있는지 확인
                    role_policies = [r for r in resources 
                                   if r.get('type') == 'aws_iam_role_policy' 
                                   and role_name in str(r.get('config', {}))]
                    
                    for policy in role_policies:
                        policy_content = str(policy.get('config', {}))
                        
                        # AdministratorAccess 또는 위험한 액션 체크
                        if 'AdministratorAccess' in policy_content or any(
                            action in policy_content for action in self.escalation_actions.keys()
                        ):
                            path = EscalationPath(
                                start_resource=user_name,
                                end_resource=role_name,
                                path=[user_name, role_name, policy.get('name', '')],
                                risk_score=85,
                                escalation_type='multi_hop',
                                description=f'{user_name} → {role_name} 경로로 권한 상승 가능',
                                evidence=[
                                    f'사용자 {user_name}이(가) 역할 {role_name}을(를) 가정 가능',
                                    f'역할이 위험한 권한 보유'
                                ]
                            )
                            paths.append(path)
        
        return paths
    
    def _analyze_role_chains(self, resources: List[Dict]) -> List[EscalationPath]:
        """역할 체인 분석 (역할 → 역할 → 역할)"""
        paths = []
        
        roles = [r for r in resources if r.get('type') == 'aws_iam_role']
        
        for role1 in roles:
            role1_name = role1.get('name', '')
            
            # role1이 가정할 수 있는 다른 역할 찾기
            role1_policies = [r for r in resources 
                            if r.get('type') == 'aws_iam_role_policy' 
                            and role1_name in str(r.get('config', {}))]
            
            for policy in role1_policies:
                policy_content = str(policy.get('config', {}))
                
                # sts:AssumeRole 권한이 있는지 확인
                if 'sts:AssumeRole' in policy_content:
                    # 어떤 역할을 가정할 수 있는지 확인
                    for role2 in roles:
                        if role1_name == role2.get('name', ''):
                            continue
                        
                        role2_name = role2.get('name', '')
                        
                        # role2의 assume_role_policy 확인
                        assume_policy = str(role2.get('config', {}).get('assume_role_policy', ''))
                        
                        if role1_name in assume_policy or '"AWS": "*"' in assume_policy:
                            # role2가 위험한 권한을 가지고 있는지 확인
                            role2_policies = [r for r in resources 
                                           if r.get('type') == 'aws_iam_role_policy_attachment' 
                                           and role2_name in str(r.get('config', {}))]
                            
                            for r2_policy in role2_policies:
                                policy_arn = str(r2_policy.get('config', {}).get('policy_arn', ''))
                                
                                if 'AdministratorAccess' in policy_arn:
                                    path = EscalationPath(
                                        start_resource=role1_name,
                                        end_resource=role2_name,
                                        path=[role1_name, role2_name],
                                        risk_score=90,
                                        escalation_type='role_chain',
                                        description=f'역할 체인을 통한 권한 상승: {role1_name} → {role2_name}',
                                        evidence=[
                                            f'{role1_name}이(가) {role2_name}을(를) 가정 가능',
                                            f'{role2_name}이(가) 관리자 권한 보유'
                                        ]
                                    )
                                    paths.append(path)
        
        return paths
    
    def get_escalation_statistics(self, paths: List[EscalationPath]) -> Dict:
        """권한 상승 경로 통계"""
        if not paths:
            return {
                'total_paths': 0,
                'by_type': {},
                'by_risk_level': {'high': 0, 'medium': 0, 'low': 0},
                'average_risk': 0.0
            }
        
        stats = {
            'total_paths': len(paths),
            'by_type': {},
            'by_risk_level': {
                'high': len([p for p in paths if p.risk_score >= 80]),
                'medium': len([p for p in paths if 50 <= p.risk_score < 80]),
                'low': len([p for p in paths if p.risk_score < 50])
            },
            'average_risk': sum(p.risk_score for p in paths) / len(paths)
        }
        
        # 타입별 집계
        for path in paths:
            escalation_type = path.escalation_type
            if escalation_type not in stats['by_type']:
                stats['by_type'][escalation_type] = 0
            stats['by_type'][escalation_type] += 1
        
        return stats

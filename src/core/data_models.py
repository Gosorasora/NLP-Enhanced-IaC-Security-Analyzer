"""
NLP 기반 IaC 보안 분석기의 핵심 데이터 모델들
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import json


class ResourceType(Enum):
    """지원되는 IAM 리소스 타입들의 열거형"""
    USER = "aws_iam_user"
    ROLE = "aws_iam_role"
    POLICY = "aws_iam_policy"
    GROUP = "aws_iam_group"
    INSTANCE_PROFILE = "aws_iam_instance_profile"
    ACCESS_KEY = "aws_iam_access_key"
    ROLE_POLICY = "aws_iam_role_policy"
    USER_POLICY = "aws_iam_user_policy"
    GROUP_POLICY = "aws_iam_group_policy"
    POLICY_ATTACHMENT = "aws_iam_policy_attachment"
    ROLE_POLICY_ATTACHMENT = "aws_iam_role_policy_attachment"
    USER_POLICY_ATTACHMENT = "aws_iam_user_policy_attachment"
    GROUP_POLICY_ATTACHMENT = "aws_iam_group_policy_attachment"


class RiskLevel(Enum):
    """일관된 위험도 분류를 위한 위험 수준 열거형"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IAMResource:
    """
    Terraform 설정에서 추출된 IAM 리소스를 나타냅니다.
    
    이 클래스는 IAM 리소스의 설정, 메타데이터, 관계를 포함한
    모든 관련 정보를 캡슐화합니다.
    """
    
    # 핵심 식별 정보
    resource_type: ResourceType
    name: str
    terraform_address: str  # 예: "aws_iam_role.example_role"
    
    # 리소스 속성
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    # 메타데이터
    arn: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    comments: List[str] = field(default_factory=list)
    
    # 정책 정보
    inline_policies: List[Dict[str, Any]] = field(default_factory=list)
    attached_policies: List[str] = field(default_factory=list)
    
    # 관계 정보
    assume_role_policy: Optional[Dict[str, Any]] = None
    trust_relationships: List[str] = field(default_factory=list)
    
    # 파일 위치 정보
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    def __post_init__(self):
        """초기화 후 처리"""
        # resource_type이 ResourceType 열거형인지 확인
        if isinstance(self.resource_type, str):
            try:
                self.resource_type = ResourceType(self.resource_type)
            except ValueError:
                # 알 수 없는 리소스 타입을 우아하게 처리
                pass
    
    @property
    def display_name(self) -> str:
        """리소스의 사람이 읽기 쉬운 표시 이름을 가져옵니다."""
        return self.attributes.get('name', self.name)
    
    @property
    def description(self) -> str:
        """속성이나 주석에서 리소스 설명을 가져옵니다."""
        # 먼저 속성에서 설명을 가져오려고 시도
        desc = self.attributes.get('description', '')
        if not desc and self.comments:
            desc = ' '.join(self.comments)
        return desc
    
    def get_text_content(self) -> str:
        """
        NLP 분석을 위해 이 리소스와 관련된 모든 텍스트 내용을 가져옵니다.
        
        Returns:
            이름, 설명, 주석 및 관련 속성의 결합된 텍스트
        """
        text_parts = []
        
        # 기본 속성들을 안전하게 추가
        if self.display_name:
            text_parts.append(str(self.display_name))
        if self.description:
            text_parts.append(str(self.description))
        if self.comments:
            text_parts.append(' '.join(str(comment) for comment in self.comments))
        
        # 관련 문자열 속성 추가
        for key, value in self.attributes.items():
            if key in ['description', 'name', 'path']:
                if isinstance(value, str):
                    text_parts.append(value)
                elif isinstance(value, list):
                    # 리스트인 경우 문자열로 변환
                    for item in value:
                        if item:
                            text_parts.append(str(item))
        
        return ' '.join(filter(None, text_parts))
    
    def has_wildcard_permissions(self) -> bool:
        """리소스가 정책에서 와일드카드 권한을 가지고 있는지 확인합니다."""
        # 인라인 정책 확인
        for policy in self.inline_policies:
            if self._policy_has_wildcards(policy):
                return True
        
        # assume role 정책 확인
        if self.assume_role_policy and self._policy_has_wildcards(self.assume_role_policy):
            return True
        
        return False
    
    def _policy_has_wildcards(self, policy: Dict[str, Any]) -> bool:
        """정책 문서가 와일드카드 권한을 포함하는지 확인합니다."""
        if not isinstance(policy, dict):
            return False
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                if isinstance(action, str) and ('*' in action or action == '*'):
                    return True
        
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """리소스를 딕셔너리 형태로 변환합니다."""
        return {
            'resource_type': self.resource_type.value if isinstance(self.resource_type, ResourceType) else str(self.resource_type),
            'name': self.name,
            'terraform_address': self.terraform_address,
            'attributes': self.attributes,
            'arn': self.arn,
            'tags': self.tags,
            'comments': self.comments,
            'inline_policies': self.inline_policies,
            'attached_policies': self.attached_policies,
            'assume_role_policy': self.assume_role_policy,
            'trust_relationships': self.trust_relationships,
            'file_path': self.file_path,
            'line_number': self.line_number
        }


@dataclass
class RiskAnalysis:
    """
    Represents the risk analysis results for an IAM resource.
    
    Contains both keyword-based and semantic analysis results along with
    the final computed risk score.
    """
    
    # Risk scores (0.0 to 1.0)
    keyword_risk_score: float = 0.0
    semantic_risk_score: float = 0.0
    final_risk_score: float = 0.0
    
    # Analysis details
    matched_keywords: List[str] = field(default_factory=list)
    semantic_similarities: Dict[str, float] = field(default_factory=dict)
    
    # Risk factors
    risk_factors: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_timestamp: Optional[str] = None
    model_version: Optional[str] = None
    
    @property
    def risk_level(self) -> RiskLevel:
        """Determine risk level based on final risk score."""
        if self.final_risk_score >= 0.9:
            return RiskLevel.CRITICAL
        elif self.final_risk_score >= 0.7:
            return RiskLevel.HIGH
        elif self.final_risk_score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def add_risk_factor(self, factor: str):
        """Add a risk factor to the analysis."""
        if factor not in self.risk_factors:
            self.risk_factors.append(factor)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert risk analysis to dictionary representation."""
        return {
            'keyword_risk_score': self.keyword_risk_score,
            'semantic_risk_score': self.semantic_risk_score,
            'final_risk_score': self.final_risk_score,
            'matched_keywords': self.matched_keywords,
            'semantic_similarities': self.semantic_similarities,
            'risk_factors': self.risk_factors,
            'risk_level': self.risk_level.value,
            'analysis_timestamp': self.analysis_timestamp,
            'model_version': self.model_version
        }


@dataclass
class Path:
    """
    Represents a path through the IAM resource graph.
    
    A path consists of a sequence of resources connected by relationships
    that could potentially lead to privilege escalation.
    """
    
    # Path structure
    nodes: List[str] = field(default_factory=list)  # Resource identifiers
    edges: List[tuple] = field(default_factory=list)  # (source, target, relationship_type)
    
    # Path metadata
    start_resource: Optional[str] = None
    target_permissions: List[str] = field(default_factory=list)
    
    # Path properties
    length: int = 0
    
    def __post_init__(self):
        """Post-initialization processing."""
        if not self.length and self.nodes:
            self.length = len(self.nodes)
        
        if not self.start_resource and self.nodes:
            self.start_resource = self.nodes[0]
    
    @property
    def end_resource(self) -> Optional[str]:
        """Get the final resource in the path."""
        return self.nodes[-1] if self.nodes else None
    
    def add_step(self, source: str, target: str, relationship_type: str):
        """Add a step to the path."""
        if not self.nodes:
            self.nodes.append(source)
        
        self.nodes.append(target)
        self.edges.append((source, target, relationship_type))
        self.length = len(self.nodes)
    
    def contains_resource(self, resource_id: str) -> bool:
        """Check if path contains a specific resource."""
        return resource_id in self.nodes
    
    def get_relationship_types(self) -> Set[str]:
        """Get all relationship types used in this path."""
        return {edge[2] for edge in self.edges}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert path to dictionary representation."""
        return {
            'nodes': self.nodes,
            'edges': [{'source': e[0], 'target': e[1], 'type': e[2]} for e in self.edges],
            'start_resource': self.start_resource,
            'target_permissions': self.target_permissions,
            'length': self.length
        }


@dataclass
class RankedPath:
    """
    Represents a path with associated risk score and ranking information.
    
    This extends the basic Path with risk analysis results and provides
    comparison capabilities for path ranking.
    """
    
    # Core path information
    path: Path
    
    # Risk assessment
    risk_score: float = 0.0
    node_risk_scores: List[float] = field(default_factory=list)
    edge_risk_scores: List[float] = field(default_factory=list)
    
    # Analysis details
    risk_explanation: str = ""
    escalation_type: str = ""  # e.g., "role_assumption", "policy_attachment"
    
    # Ranking information
    rank: Optional[int] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        # Ensure we have risk scores for all nodes and edges
        if not self.node_risk_scores and self.path.nodes:
            self.node_risk_scores = [0.0] * len(self.path.nodes)
        
        if not self.edge_risk_scores and self.path.edges:
            self.edge_risk_scores = [0.0] * len(self.path.edges)
    
    @property
    def description(self) -> str:
        """Get a human-readable description of the path."""
        if self.risk_explanation:
            return self.risk_explanation
        
        if not self.path.nodes:
            return "Empty path"
        
        start = self.path.start_resource or "Unknown"
        end = self.path.end_resource or "Unknown"
        return f"Path from {start} to {end} ({self.path.length} steps)"
    
    @property
    def risk_level(self) -> RiskLevel:
        """Determine risk level based on risk score."""
        if self.risk_score >= 0.9:
            return RiskLevel.CRITICAL
        elif self.risk_score >= 0.7:
            return RiskLevel.HIGH
        elif self.risk_score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def __lt__(self, other: 'RankedPath') -> bool:
        """Enable sorting by risk score (descending)."""
        return self.risk_score > other.risk_score
    
    def __eq__(self, other: 'RankedPath') -> bool:
        """Check equality based on path and risk score."""
        if not isinstance(other, RankedPath):
            return False
        return (self.path.nodes == other.path.nodes and 
                abs(self.risk_score - other.risk_score) < 1e-6)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ranked path to dictionary representation."""
        return {
            'path': self.path.to_dict(),
            'risk_score': self.risk_score,
            'node_risk_scores': self.node_risk_scores,
            'edge_risk_scores': self.edge_risk_scores,
            'risk_explanation': self.risk_explanation,
            'escalation_type': self.escalation_type,
            'risk_level': self.risk_level.value,
            'rank': self.rank,
            'description': self.description
        }
    
    def to_json(self) -> str:
        """Convert ranked path to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
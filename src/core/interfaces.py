"""
NLP 기반 IaC 보안 분석기 모듈들을 위한 추상 인터페이스

이 인터페이스들은 각 모듈이 구현해야 하는 계약을 정의하여
모듈성과 테스트 가능성을 제공합니다.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import networkx as nx

from src.core.data_models import IAMResource, RiskAnalysis, Path, RankedPath
from config.settings import Config


class IaCParserModule(ABC):
    """
    Infrastructure as Code 파싱 및 그래프 구축을 위한 추상 인터페이스
    
    이 모듈은 Terraform 파일 파싱, IAM 리소스 추출,
    기본 그래프 구조 구축을 담당합니다.
    """
    
    def __init__(self, config: Config):
        """설정으로 파서 모듈을 초기화합니다."""
        self.config = config
    
    @abstractmethod
    def parse_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        디렉토리 내의 모든 Terraform 파일을 파싱합니다.
        
        Args:
            directory_path: .tf 파일들이 있는 디렉토리 경로
            
        Returns:
            파싱된 Terraform 설정 데이터를 포함하는 딕셔너리
            
        Raises:
            FileNotFoundError: 디렉토리가 존재하지 않는 경우
            ValueError: 유효한 Terraform 파일이 없는 경우
        """
        pass
    
    @abstractmethod
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a single Terraform file.
        
        Args:
            file_path: Path to .tf file
            
        Returns:
            Dictionary containing parsed configuration data
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file contains invalid Terraform syntax
        """
        pass
    
    @abstractmethod
    def extract_iam_resources(self, parsed_data: Dict[str, Any]) -> List[IAMResource]:
        """
        Extract IAM resources from parsed Terraform data.
        
        Args:
            parsed_data: Dictionary containing parsed Terraform configuration
            
        Returns:
            List of IAMResource objects representing all IAM resources found
        """
        pass
    
    @abstractmethod
    def build_graph(self, resources: List[IAMResource]) -> nx.DiGraph:
        """
        Build a directed graph from IAM resources.
        
        Args:
            resources: List of IAM resources to include in graph
            
        Returns:
            NetworkX directed graph with resources as nodes and relationships as edges
        """
        pass
    
    @abstractmethod
    def get_resource_relationships(self, resources: List[IAMResource]) -> List[Tuple[str, str, str]]:
        """
        Identify relationships between IAM resources.
        
        Args:
            resources: List of IAM resources to analyze
            
        Returns:
            List of tuples (source_id, target_id, relationship_type)
        """
        pass


class NLPContextModule(ABC):
    """
    Abstract interface for NLP-based context analysis and risk assessment.
    
    This module enhances the graph with semantic risk scores using natural
    language processing techniques.
    """
    
    def __init__(self, config: Config):
        """Initialize the NLP module with configuration."""
        self.config = config
    
    @abstractmethod
    def analyze_resource_risk(self, resource: IAMResource) -> RiskAnalysis:
        """
        Analyze risk for a single IAM resource using NLP techniques.
        
        Args:
            resource: IAM resource to analyze
            
        Returns:
            RiskAnalysis object containing risk scores and analysis details
        """
        pass
    
    @abstractmethod
    def analyze_keyword_risk(self, text: str) -> Tuple[float, List[str]]:
        """
        Analyze risk based on keyword matching.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, matched_keywords)
        """
        pass
    
    @abstractmethod
    def analyze_semantic_risk(self, text: str) -> Tuple[float, Dict[str, float]]:
        """
        Analyze risk using semantic similarity with risk concepts.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, similarity_scores_by_concept)
        """
        pass
    
    @abstractmethod
    def enhance_graph(self, graph: nx.DiGraph) -> nx.DiGraph:
        """
        Enhance graph nodes and edges with NLP-derived risk scores.
        
        Args:
            graph: Original graph with IAM resources
            
        Returns:
            Enhanced graph with risk scores added to nodes and edges
        """
        pass
    
    @abstractmethod
    def batch_analyze_resources(self, resources: List[IAMResource]) -> Dict[str, RiskAnalysis]:
        """
        Perform batch analysis of multiple resources for efficiency.
        
        Args:
            resources: List of IAM resources to analyze
            
        Returns:
            Dictionary mapping resource IDs to RiskAnalysis objects
        """
        pass


class AttackPathModule(ABC):
    """
    Abstract interface for privilege escalation path detection and analysis.
    
    This module identifies and ranks potential attack paths through the
    enhanced IAM resource graph.
    """
    
    def __init__(self, config: Config):
        """Initialize the attack path module with configuration."""
        self.config = config
    
    @abstractmethod
    def find_paths(self, graph: nx.DiGraph, start_resource: str, 
                   target_permissions: List[str]) -> List[Path]:
        """
        Find all possible paths from start resource to target permissions.
        
        Args:
            graph: Enhanced graph with risk scores
            start_resource: Starting resource identifier
            target_permissions: List of target permissions to reach
            
        Returns:
            List of Path objects representing possible escalation routes
        """
        pass
    
    @abstractmethod
    def find_all_paths(self, graph: nx.DiGraph, start_resource: str,
                       target_permissions: List[str]) -> List[Path]:
        """
        Find all paths from a starting resource, including multi-hop paths.
        
        Args:
            graph: Enhanced graph with risk scores
            start_resource: Starting resource identifier
            target_permissions: List of target permissions to reach
            
        Returns:
            List of all possible Path objects
        """
        pass
    
    @abstractmethod
    def calculate_path_risk(self, path: Path, graph: nx.DiGraph) -> float:
        """
        Calculate risk score for a specific path.
        
        Args:
            path: Path to analyze
            graph: Enhanced graph with risk scores
            
        Returns:
            Risk score for the path (0.0 to 1.0)
        """
        pass
    
    @abstractmethod
    def rank_paths(self, paths: List[Path], graph: nx.DiGraph) -> List[RankedPath]:
        """
        Rank paths by risk score and return sorted list.
        
        Args:
            paths: List of paths to rank
            graph: Enhanced graph with risk scores
            
        Returns:
            List of RankedPath objects sorted by risk (highest first)
        """
        pass
    
    @abstractmethod
    def find_highest_risk_paths(self, paths: List[Path], 
                                graph: nx.DiGraph, top_k: int = 10) -> List[RankedPath]:
        """
        Find the top-k highest risk paths from a list of paths.
        
        Args:
            paths: List of paths to analyze
            graph: Enhanced graph with risk scores
            top_k: Number of top paths to return
            
        Returns:
            List of top-k RankedPath objects
        """
        pass
    
    @abstractmethod
    def find_all_escalation_paths(self, graph: nx.DiGraph, 
                                  target_permissions: List[str]) -> List[RankedPath]:
        """
        Find all potential privilege escalation paths in the graph.
        
        Args:
            graph: Enhanced graph with risk scores
            target_permissions: List of target permissions to reach
            
        Returns:
            List of all RankedPath objects found, sorted by risk
        """
        pass


class VisualizationModule(ABC):
    """
    Abstract interface for visualization and reporting functionality.
    
    This module generates interactive visualizations and comprehensive
    reports of the security analysis results.
    """
    
    def __init__(self, config: Config):
        """Initialize the visualization module with configuration."""
        self.config = config
    
    @abstractmethod
    def create_interactive_graph(self, graph: nx.DiGraph, 
                                 attack_paths: List[RankedPath]) -> str:
        """
        Create an interactive HTML visualization of the graph and attack paths.
        
        Args:
            graph: Enhanced graph with risk scores
            attack_paths: List of ranked attack paths to highlight
            
        Returns:
            HTML string containing interactive visualization
        """
        pass
    
    @abstractmethod
    def highlight_attack_paths(self, graph: nx.DiGraph, 
                               attack_paths: List[RankedPath]) -> nx.DiGraph:
        """
        Add visual highlighting to graph for attack paths.
        
        Args:
            graph: Original enhanced graph
            attack_paths: List of attack paths to highlight
            
        Returns:
            Graph with visual attributes added for path highlighting
        """
        pass
    
    @abstractmethod
    def generate_report(self, analysis_data: Dict[str, Any]) -> 'AnalysisReport':
        """
        Generate a comprehensive analysis report.
        
        Args:
            analysis_data: Dictionary containing all analysis results
            
        Returns:
            AnalysisReport object with structured findings
        """
        pass
    
    @abstractmethod
    def export_results(self, analysis_data: Dict[str, Any], 
                       output_path: str, format_type: str = "html") -> str:
        """
        Export analysis results to specified format and location.
        
        Args:
            analysis_data: Dictionary containing all analysis results
            output_path: Path where results should be saved
            format_type: Output format ("html", "json", "csv")
            
        Returns:
            Path to the exported file
        """
        pass
    
    @abstractmethod
    def create_summary_statistics(self, graph: nx.DiGraph, 
                                  attack_paths: List[RankedPath]) -> Dict[str, Any]:
        """
        Generate summary statistics for the analysis.
        
        Args:
            graph: Enhanced graph with risk scores
            attack_paths: List of ranked attack paths
            
        Returns:
            Dictionary containing summary statistics and metrics
        """
        pass


@dataclass
class AnalysisReport:
    """
    Structured analysis report containing all findings and recommendations.
    """
    
    # Summary information
    total_resources: int = 0
    high_risk_resources: int = 0
    total_attack_paths: int = 0
    critical_paths: int = 0
    
    # Detailed findings
    resource_summary: Dict[str, int] = None
    risk_distribution: Dict[str, int] = None
    top_attack_paths: List[RankedPath] = None
    recommendations: List[str] = None
    
    # Metadata
    analysis_timestamp: str = ""
    configuration_used: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize default values for mutable fields."""
        if self.resource_summary is None:
            self.resource_summary = {}
        if self.risk_distribution is None:
            self.risk_distribution = {}
        if self.top_attack_paths is None:
            self.top_attack_paths = []
        if self.recommendations is None:
            self.recommendations = []
        if self.configuration_used is None:
            self.configuration_used = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary representation."""
        return {
            'summary': {
                'total_resources': self.total_resources,
                'high_risk_resources': self.high_risk_resources,
                'total_attack_paths': self.total_attack_paths,
                'critical_paths': self.critical_paths
            },
            'resource_summary': self.resource_summary,
            'risk_distribution': self.risk_distribution,
            'top_attack_paths': [path.to_dict() for path in self.top_attack_paths],
            'recommendations': self.recommendations,
            'metadata': {
                'analysis_timestamp': self.analysis_timestamp,
                'configuration_used': self.configuration_used
            }
        }
    
    def to_json(self) -> str:
        """Convert report to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)
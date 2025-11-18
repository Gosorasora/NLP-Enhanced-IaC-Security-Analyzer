"""
NLP 기반 IaC 보안 분석기의 설정 및 관리
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None


@dataclass
class NLPConfig:
    """NLP 분석 설정을 위한 구성"""
    model_name: str = "bert-base-uncased"
    max_sequence_length: int = 512
    batch_size: int = 32
    cache_predictions: bool = True
    semantic_similarity_threshold: float = 0.7
    
    # 위험 키워드 설정
    risk_keywords: Dict[str, float] = field(default_factory=lambda: {
        "admin": 0.9,
        "root": 0.95,
        "full": 0.8,
        "all": 0.8,
        "wildcard": 0.85,
        "temp": 0.7,
        "temporary": 0.7,
        "test": 0.6,
        "dev": 0.5,
        "debug": 0.6,
        "bypass": 0.9,
        "override": 0.8,
        "emergency": 0.85,
        "backdoor": 0.95,
        "service": 0.4,
        "application": 0.3,
        "user": 0.2
    })
    
    # 의미론적 분석을 위한 위험 개념 구문들
    risk_concepts: List[str] = field(default_factory=lambda: [
        "administrative access",
        "full permissions",
        "policy modification",
        "role assumption",
        "privilege escalation",
        "security bypass",
        "temporary access",
        "emergency access",
        "development testing",
        "debugging access"
    ])


@dataclass
class PathDetectionConfig:
    """권한 상승 경로 탐지를 위한 설정"""
    max_path_length: int = 10
    min_risk_threshold: float = 0.3
    top_k_paths: int = 10
    
    # 위험도 계산 가중치
    keyword_weight: float = 0.4
    semantic_weight: float = 0.6
    
    # 경로 위험도 집계 방법
    node_aggregation: str = "sum"  # "sum", "max", "average"
    edge_aggregation: str = "product"  # "product", "sum", "min"


@dataclass
class VisualizationConfig:
    """시각화 및 보고서 생성을 위한 설정"""
    graph_width: str = "100%"
    graph_height: str = "800px"
    node_size_range: tuple = (20, 100)
    edge_width_range: tuple = (1, 10)
    
    # 색상 스키마
    low_risk_color: str = "#90EE90"  # 연한 녹색
    medium_risk_color: str = "#FFD700"  # 금색
    high_risk_color: str = "#FF6B6B"  # 연한 빨간색
    critical_risk_color: str = "#DC143C"  # 진홍색
    
    # 색상 코딩을 위한 위험도 임계값
    medium_risk_threshold: float = 0.4
    high_risk_threshold: float = 0.7
    critical_risk_threshold: float = 0.9


class ConfigValidator(ABC):
    """설정 검증기를 위한 추상 기본 클래스"""
    
    @abstractmethod
    def validate(self, config: 'Config') -> List[str]:
        """설정을 검증하고 오류 메시지 목록을 반환합니다."""
        pass


class DefaultConfigValidator(ConfigValidator):
    """포괄적인 검사를 포함한 기본 설정 검증기"""
    
    def validate(self, config: 'Config') -> List[str]:
        """설정을 검증하고 검증 오류 목록을 반환합니다."""
        errors = []
        
        # NLP 설정 검증
        errors.extend(self._validate_nlp_config(config.nlp))
        
        # 경로 탐지 설정 검증
        errors.extend(self._validate_path_detection_config(config.path_detection))
        
        # 시각화 설정 검증
        errors.extend(self._validate_visualization_config(config.visualization))
        
        # 일반 설정 검증
        errors.extend(self._validate_general_settings(config))
        
        return errors
    
    def _validate_nlp_config(self, nlp_config: NLPConfig) -> List[str]:
        """Validate NLP configuration."""
        errors = []
        
        if nlp_config.semantic_similarity_threshold < 0 or nlp_config.semantic_similarity_threshold > 1:
            errors.append("NLP semantic_similarity_threshold must be between 0 and 1")
        
        if nlp_config.batch_size <= 0:
            errors.append("NLP batch_size must be positive")
        
        if nlp_config.max_sequence_length <= 0:
            errors.append("NLP max_sequence_length must be positive")
        
        # Validate risk keywords
        for keyword, weight in nlp_config.risk_keywords.items():
            if not isinstance(weight, (int, float)) or weight < 0 or weight > 1:
                errors.append(f"Risk keyword '{keyword}' weight must be between 0 and 1")
        
        # Validate risk concepts
        if not nlp_config.risk_concepts:
            errors.append("At least one risk concept must be defined")
        
        return errors
    
    def _validate_path_detection_config(self, path_config: PathDetectionConfig) -> List[str]:
        """Validate path detection configuration."""
        errors = []
        
        if abs(path_config.keyword_weight + path_config.semantic_weight - 1.0) > 1e-6:
            errors.append("Path detection keyword_weight + semantic_weight must equal 1.0")
        
        if path_config.min_risk_threshold < 0 or path_config.min_risk_threshold > 1:
            errors.append("Path detection min_risk_threshold must be between 0 and 1")
        
        if path_config.max_path_length <= 0:
            errors.append("Path detection max_path_length must be positive")
        
        if path_config.top_k_paths <= 0:
            errors.append("Path detection top_k_paths must be positive")
        
        valid_aggregations = {"sum", "max", "average", "product", "min"}
        if path_config.node_aggregation not in valid_aggregations:
            errors.append(f"Invalid node_aggregation: {path_config.node_aggregation}")
        
        if path_config.edge_aggregation not in valid_aggregations:
            errors.append(f"Invalid edge_aggregation: {path_config.edge_aggregation}")
        
        return errors
    
    def _validate_visualization_config(self, viz_config: VisualizationConfig) -> List[str]:
        """Validate visualization configuration."""
        errors = []
        
        # Validate risk thresholds
        thresholds = [
            viz_config.medium_risk_threshold,
            viz_config.high_risk_threshold,
            viz_config.critical_risk_threshold
        ]
        
        if not all(0 <= t <= 1 for t in thresholds):
            errors.append("All visualization risk thresholds must be between 0 and 1")
        
        if not (thresholds[0] < thresholds[1] < thresholds[2]):
            errors.append("Visualization risk thresholds must be in ascending order")
        
        # Validate size ranges
        if len(viz_config.node_size_range) != 2 or viz_config.node_size_range[0] >= viz_config.node_size_range[1]:
            errors.append("Node size range must be a tuple of (min, max) with min < max")
        
        if len(viz_config.edge_width_range) != 2 or viz_config.edge_width_range[0] >= viz_config.edge_width_range[1]:
            errors.append("Edge width range must be a tuple of (min, max) with min < max")
        
        return errors
    
    def _validate_general_settings(self, config: 'Config') -> List[str]:
        """Validate general configuration settings."""
        errors = []
        
        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if config.log_level not in valid_log_levels:
            errors.append(f"Invalid log_level: {config.log_level}")
        
        valid_output_formats = {"html", "json", "both"}
        if config.output_format not in valid_output_formats:
            errors.append(f"Invalid output_format: {config.output_format}")
        
        if config.max_workers <= 0:
            errors.append("max_workers must be positive")
        
        if config.memory_limit_gb <= 0:
            errors.append("memory_limit_gb must be positive")
        
        return errors


@dataclass
class Config:
    """Main configuration class for the NLP-enhanced IaC security analyzer."""
    nlp: NLPConfig = field(default_factory=NLPConfig)
    path_detection: PathDetectionConfig = field(default_factory=PathDetectionConfig)
    visualization: VisualizationConfig = field(default_factory=VisualizationConfig)
    
    # General settings
    verbose: bool = False
    log_level: str = "INFO"
    output_format: str = "html"  # "html", "json", "both"
    
    # Performance settings
    max_workers: int = 4
    memory_limit_gb: float = 8.0
    
    # Configuration management
    _validator: ConfigValidator = field(default_factory=DefaultConfigValidator, init=False)
    
    @classmethod
    def load_config(cls, config_path: Optional[str] = None, validator: Optional[ConfigValidator] = None) -> 'Config':
        """
        Load configuration from file or use defaults.
        
        Args:
            config_path: Path to YAML or JSON configuration file
            validator: Custom validator instance (uses DefaultConfigValidator if None)
            
        Returns:
            Config instance with loaded settings
            
        Raises:
            ValueError: If configuration validation fails
        """
        config = cls()
        
        if validator:
            config._validator = validator
        
        # Load default configuration first
        default_yaml_path = Path(__file__).parent / "default_config.yaml"
        default_json_path = Path(__file__).parent / "default_config.json"
        
        if default_yaml_path.exists() and YAML_AVAILABLE:
            config._load_config_file(str(default_yaml_path))
        elif default_json_path.exists():
            config._load_config_file(str(default_json_path))
        
        # Override with user-specified configuration
        if config_path and Path(config_path).exists():
            config._load_config_file(config_path)
        
        # Override with environment variables if present
        config._load_from_environment()
        
        # Validate configuration
        validation_errors = config.validate()
        if validation_errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in validation_errors)
            raise ValueError(error_msg)
        
        return config
    
    def _load_config_file(self, config_path: str):
        """Load configuration from a YAML or JSON file."""
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.json'):
                    config_data = json.load(f)
                elif config_path.endswith(('.yaml', '.yml')):
                    if not YAML_AVAILABLE:
                        raise ImportError("PyYAML is required to load YAML configuration files")
                    config_data = yaml.safe_load(f)
                else:
                    # Try to detect format by content
                    content = f.read()
                    f.seek(0)
                    if content.strip().startswith('{'):
                        config_data = json.load(f)
                    elif YAML_AVAILABLE:
                        config_data = yaml.safe_load(f)
                    else:
                        raise ValueError("Cannot determine configuration file format and PyYAML is not available")
            
            # Update configuration with loaded data
            if 'nlp' in config_data:
                self._update_nlp_config(config_data['nlp'])
            
            if 'path_detection' in config_data:
                self._update_path_detection_config(config_data['path_detection'])
            
            if 'visualization' in config_data:
                self._update_visualization_config(config_data['visualization'])
            
            # Update general settings
            for key in ['verbose', 'log_level', 'output_format', 'max_workers', 'memory_limit_gb']:
                if key in config_data:
                    setattr(self, key, config_data[key])
                    
        except Exception as e:
            logging.warning(f"Failed to load config from {config_path}: {e}")
            logging.info("Continuing with existing configuration")
    
    def _update_nlp_config(self, nlp_data: Dict[str, Any]):
        """Update NLP configuration from loaded data."""
        for key, value in nlp_data.items():
            if hasattr(self.nlp, key):
                setattr(self.nlp, key, value)
    
    def _update_path_detection_config(self, path_data: Dict[str, Any]):
        """Update path detection configuration from loaded data."""
        for key, value in path_data.items():
            if hasattr(self.path_detection, key):
                setattr(self.path_detection, key, value)
    
    def _update_visualization_config(self, viz_data: Dict[str, Any]):
        """Update visualization configuration from loaded data."""
        for key, value in viz_data.items():
            if hasattr(self.visualization, key):
                setattr(self.visualization, key, value)
    
    def _load_from_environment(self):
        """Load configuration overrides from environment variables."""
        env_mappings = {
            'NLP_MODEL_NAME': ('nlp', 'model_name'),
            'MAX_PATH_LENGTH': ('path_detection', 'max_path_length'),
            'RISK_THRESHOLD': ('path_detection', 'min_risk_threshold'),
            'VERBOSE': ('verbose',),
            'LOG_LEVEL': ('log_level',),
            'MAX_WORKERS': ('max_workers',)
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    # Convert string values to appropriate types
                    if env_var in ['MAX_PATH_LENGTH', 'MAX_WORKERS']:
                        value = int(value)
                    elif env_var in ['RISK_THRESHOLD']:
                        value = float(value)
                    elif env_var == 'VERBOSE':
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    
                    # Set the configuration value
                    if len(config_path) == 1:
                        setattr(self, config_path[0], value)
                    elif len(config_path) == 2:
                        config_obj = getattr(self, config_path[0])
                        setattr(config_obj, config_path[1], value)
                        
                except (ValueError, AttributeError) as e:
                    logging.warning(f"Invalid environment variable {env_var}={value}: {e}")
    
    def enable_verbose_logging(self):
        """Enable verbose logging and set appropriate log level."""
        self.verbose = True
        self.log_level = "DEBUG"
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, self.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def validate(self) -> List[str]:
        """
        Validate configuration settings using the configured validator.
        
        Returns:
            List of validation error messages
        """
        return self._validator.validate(self)
    
    def save_config(self, config_path: str, format: str = "yaml"):
        """
        Save current configuration to file.
        
        Args:
            config_path: Path where to save the configuration
            format: File format ("yaml" or "json")
        """
        config_dict = self.to_dict()
        
        with open(config_path, 'w') as f:
            if format.lower() == "json":
                json.dump(config_dict, f, indent=2)
            elif format.lower() in ("yaml", "yml"):
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML is required to save YAML configuration files")
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")
    
    def merge_config(self, other_config: Union['Config', Dict[str, Any]]):
        """
        Merge another configuration into this one.
        
        Args:
            other_config: Another Config instance or dictionary to merge
        """
        if isinstance(other_config, Config):
            other_dict = other_config.to_dict()
        else:
            other_dict = other_config
        
        # Merge NLP configuration
        if 'nlp' in other_dict:
            self._update_nlp_config(other_dict['nlp'])
        
        # Merge path detection configuration
        if 'path_detection' in other_dict:
            self._update_path_detection_config(other_dict['path_detection'])
        
        # Merge visualization configuration
        if 'visualization' in other_dict:
            self._update_visualization_config(other_dict['visualization'])
        
        # Merge general settings
        for key in ['verbose', 'log_level', 'output_format', 'max_workers', 'memory_limit_gb']:
            if key in other_dict:
                setattr(self, key, other_dict[key])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary format."""
        return {
            'nlp': {
                'model_name': self.nlp.model_name,
                'max_sequence_length': self.nlp.max_sequence_length,
                'batch_size': self.nlp.batch_size,
                'cache_predictions': self.nlp.cache_predictions,
                'semantic_similarity_threshold': self.nlp.semantic_similarity_threshold,
                'risk_keywords': self.nlp.risk_keywords,
                'risk_concepts': self.nlp.risk_concepts
            },
            'path_detection': {
                'max_path_length': self.path_detection.max_path_length,
                'min_risk_threshold': self.path_detection.min_risk_threshold,
                'top_k_paths': self.path_detection.top_k_paths,
                'keyword_weight': self.path_detection.keyword_weight,
                'semantic_weight': self.path_detection.semantic_weight,
                'node_aggregation': self.path_detection.node_aggregation,
                'edge_aggregation': self.path_detection.edge_aggregation
            },
            'visualization': {
                'graph_width': self.visualization.graph_width,
                'graph_height': self.visualization.graph_height,
                'node_size_range': self.visualization.node_size_range,
                'edge_width_range': self.visualization.edge_width_range,
                'low_risk_color': self.visualization.low_risk_color,
                'medium_risk_color': self.visualization.medium_risk_color,
                'high_risk_color': self.visualization.high_risk_color,
                'critical_risk_color': self.visualization.critical_risk_color,
                'medium_risk_threshold': self.visualization.medium_risk_threshold,
                'high_risk_threshold': self.visualization.high_risk_threshold,
                'critical_risk_threshold': self.visualization.critical_risk_threshold
            },
            'verbose': self.verbose,
            'log_level': self.log_level,
            'output_format': self.output_format,
            'max_workers': self.max_workers,
            'memory_limit_gb': self.memory_limit_gb
        }
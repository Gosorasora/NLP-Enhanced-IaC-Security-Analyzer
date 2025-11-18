"""
Advanced configuration management for the NLP-enhanced IaC security analyzer.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

from .settings import Config, ConfigValidator, DefaultConfigValidator


class ConfigurationError(Exception):
    """Exception raised for configuration-related errors."""
    pass


@dataclass
class ConfigProfile:
    """Configuration profile for different analysis scenarios."""
    name: str
    description: str
    config: Config
    tags: List[str] = field(default_factory=list)


class ConfigManager:
    """Advanced configuration manager with profiles and validation."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Directory to store configuration files
        """
        self.config_dir = Path(config_dir) if config_dir else Path.home() / ".iac_analyzer"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.profiles_file = self.config_dir / "profiles.json"
        self.current_profile = "default"
        self._profiles: Dict[str, ConfigProfile] = {}
        self._validators: Dict[str, ConfigValidator] = {
            "default": DefaultConfigValidator()
        }
        
        # Load existing profiles
        self._load_profiles()
    
    def create_profile(self, name: str, config: Config, description: str = "", tags: List[str] = None) -> ConfigProfile:
        """
        Create a new configuration profile.
        
        Args:
            name: Profile name
            config: Configuration instance
            description: Profile description
            tags: Profile tags for categorization
            
        Returns:
            Created ConfigProfile instance
        """
        if tags is None:
            tags = []
        
        # Validate configuration
        validation_errors = config.validate()
        if validation_errors:
            raise ConfigurationError(f"Invalid configuration: {validation_errors}")
        
        profile = ConfigProfile(
            name=name,
            description=description,
            config=config,
            tags=tags
        )
        
        self._profiles[name] = profile
        self._save_profiles()
        
        return profile
    
    def get_profile(self, name: str) -> Optional[ConfigProfile]:
        """Get configuration profile by name."""
        return self._profiles.get(name)
    
    def list_profiles(self, tag_filter: Optional[str] = None) -> List[ConfigProfile]:
        """
        List all configuration profiles.
        
        Args:
            tag_filter: Optional tag to filter profiles
            
        Returns:
            List of matching profiles
        """
        profiles = list(self._profiles.values())
        
        if tag_filter:
            profiles = [p for p in profiles if tag_filter in p.tags]
        
        return profiles
    
    def delete_profile(self, name: str) -> bool:
        """
        Delete a configuration profile.
        
        Args:
            name: Profile name to delete
            
        Returns:
            True if profile was deleted, False if not found
        """
        if name in self._profiles:
            del self._profiles[name]
            self._save_profiles()
            return True
        return False
    
    def set_current_profile(self, name: str):
        """Set the current active profile."""
        if name not in self._profiles:
            raise ConfigurationError(f"Profile '{name}' not found")
        
        self.current_profile = name
    
    def get_current_config(self) -> Config:
        """Get configuration for the current profile."""
        if self.current_profile not in self._profiles:
            # Create default profile if it doesn't exist
            default_config = Config.load_config()
            self.create_profile("default", default_config, "Default configuration")
        
        return self._profiles[self.current_profile].config
    
    def register_validator(self, name: str, validator: ConfigValidator):
        """Register a custom configuration validator."""
        self._validators[name] = validator
    
    def validate_with_validator(self, config: Config, validator_name: str) -> List[str]:
        """
        Validate configuration with a specific validator.
        
        Args:
            config: Configuration to validate
            validator_name: Name of registered validator
            
        Returns:
            List of validation errors
        """
        if validator_name not in self._validators:
            raise ConfigurationError(f"Validator '{validator_name}' not found")
        
        return self._validators[validator_name].validate(config)
    
    def create_preset_profiles(self):
        """Create common preset configuration profiles."""
        presets = [
            {
                "name": "high_security",
                "description": "High security analysis with strict thresholds",
                "tags": ["security", "strict"],
                "config_overrides": {
                    "path_detection": {
                        "min_risk_threshold": 0.1,
                        "top_k_paths": 20
                    },
                    "nlp": {
                        "semantic_similarity_threshold": 0.5
                    }
                }
            },
            {
                "name": "development",
                "description": "Development-friendly analysis with relaxed thresholds",
                "tags": ["development", "relaxed"],
                "config_overrides": {
                    "path_detection": {
                        "min_risk_threshold": 0.5,
                        "top_k_paths": 5
                    },
                    "verbose": True,
                    "log_level": "DEBUG"
                }
            },
            {
                "name": "performance",
                "description": "Optimized for performance on large infrastructures",
                "tags": ["performance", "large-scale"],
                "config_overrides": {
                    "nlp": {
                        "batch_size": 64,
                        "cache_predictions": True
                    },
                    "max_workers": 8,
                    "path_detection": {
                        "max_path_length": 5
                    }
                }
            }
        ]
        
        for preset in presets:
            if preset["name"] not in self._profiles:
                base_config = Config.load_config()
                base_config.merge_config(preset["config_overrides"])
                
                self.create_profile(
                    name=preset["name"],
                    config=base_config,
                    description=preset["description"],
                    tags=preset["tags"]
                )
    
    def export_profile(self, name: str, file_path: str, format: str = "yaml"):
        """
        Export a profile configuration to file.
        
        Args:
            name: Profile name to export
            file_path: Output file path
            format: Export format ("yaml" or "json")
        """
        profile = self.get_profile(name)
        if not profile:
            raise ConfigurationError(f"Profile '{name}' not found")
        
        profile.config.save_config(file_path, format)
    
    def import_profile(self, name: str, file_path: str, description: str = "", tags: List[str] = None):
        """
        Import a profile configuration from file.
        
        Args:
            name: Name for the imported profile
            file_path: Path to configuration file
            description: Profile description
            tags: Profile tags
        """
        config = Config.load_config(file_path)
        self.create_profile(name, config, description, tags or [])
    
    def _load_profiles(self):
        """Load profiles from storage."""
        if not self.profiles_file.exists():
            return
        
        try:
            with open(self.profiles_file, 'r') as f:
                profiles_data = json.load(f)
            
            for profile_data in profiles_data:
                config = Config()
                config.merge_config(profile_data["config"])
                
                profile = ConfigProfile(
                    name=profile_data["name"],
                    description=profile_data["description"],
                    config=config,
                    tags=profile_data.get("tags", [])
                )
                
                self._profiles[profile.name] = profile
                
        except Exception as e:
            logging.warning(f"Failed to load profiles: {e}")
    
    def _save_profiles(self):
        """Save profiles to storage."""
        try:
            profiles_data = []
            for profile in self._profiles.values():
                profiles_data.append({
                    "name": profile.name,
                    "description": profile.description,
                    "config": profile.config.to_dict(),
                    "tags": profile.tags
                })
            
            with open(self.profiles_file, 'w') as f:
                json.dump(profiles_data, f, indent=2)
                
        except Exception as e:
            logging.error(f"Failed to save profiles: {e}")


class EnvironmentConfigLoader:
    """Utility class for loading configuration from environment variables."""
    
    ENV_PREFIX = "IAC_ANALYZER_"
    
    @classmethod
    def load_from_environment(cls, config: Config) -> Config:
        """
        Load configuration overrides from environment variables.
        
        Args:
            config: Base configuration to override
            
        Returns:
            Updated configuration
        """
        env_mappings = cls._get_env_mappings()
        
        for env_var, (config_path, converter) in env_mappings.items():
            full_env_var = cls.ENV_PREFIX + env_var
            value = os.getenv(full_env_var)
            
            if value is not None:
                try:
                    converted_value = converter(value)
                    cls._set_config_value(config, config_path, converted_value)
                except (ValueError, AttributeError) as e:
                    logging.warning(f"Invalid environment variable {full_env_var}={value}: {e}")
        
        return config
    
    @classmethod
    def _get_env_mappings(cls) -> Dict[str, tuple]:
        """Get mapping of environment variables to configuration paths."""
        return {
            # NLP Configuration
            'NLP_MODEL_NAME': (('nlp', 'model_name'), str),
            'NLP_BATCH_SIZE': (('nlp', 'batch_size'), int),
            'NLP_CACHE_PREDICTIONS': (('nlp', 'cache_predictions'), cls._str_to_bool),
            'NLP_SIMILARITY_THRESHOLD': (('nlp', 'semantic_similarity_threshold'), float),
            
            # Path Detection Configuration
            'MAX_PATH_LENGTH': (('path_detection', 'max_path_length'), int),
            'RISK_THRESHOLD': (('path_detection', 'min_risk_threshold'), float),
            'TOP_K_PATHS': (('path_detection', 'top_k_paths'), int),
            'KEYWORD_WEIGHT': (('path_detection', 'keyword_weight'), float),
            'SEMANTIC_WEIGHT': (('path_detection', 'semantic_weight'), float),
            
            # General Settings
            'VERBOSE': (('verbose',), cls._str_to_bool),
            'LOG_LEVEL': (('log_level',), str),
            'OUTPUT_FORMAT': (('output_format',), str),
            'MAX_WORKERS': (('max_workers',), int),
            'MEMORY_LIMIT_GB': (('memory_limit_gb',), float),
        }
    
    @staticmethod
    def _str_to_bool(value: str) -> bool:
        """Convert string to boolean."""
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @staticmethod
    def _set_config_value(config: Config, config_path: tuple, value: Any):
        """Set configuration value using path tuple."""
        if len(config_path) == 1:
            setattr(config, config_path[0], value)
        elif len(config_path) == 2:
            config_obj = getattr(config, config_path[0])
            setattr(config_obj, config_path[1], value)
        else:
            raise ValueError(f"Unsupported config path length: {config_path}")
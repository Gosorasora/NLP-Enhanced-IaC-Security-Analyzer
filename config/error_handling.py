"""
Comprehensive error handling and validation for the NLP-enhanced IaC security analyzer.

This module provides custom exceptions, error recovery strategies, and validation utilities.
"""

import logging
import traceback
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification."""
    INPUT_VALIDATION = "input_validation"
    CONFIGURATION = "configuration"
    PARSING = "parsing"
    NLP_PROCESSING = "nlp_processing"
    GRAPH_PROCESSING = "graph_processing"
    PATH_DETECTION = "path_detection"
    VISUALIZATION = "visualization"
    IO_ERROR = "io_error"
    SYSTEM_ERROR = "system_error"


@dataclass
class ErrorContext:
    """Context information for errors."""
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    details: Optional[str] = None
    suggestions: Optional[List[str]] = None
    recoverable: bool = True
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    stack_trace: Optional[str] = None


class NLPIaCAnalyzerError(Exception):
    """Base exception class for the NLP IaC Security Analyzer."""
    
    def __init__(self, context: ErrorContext):
        self.context = context
        super().__init__(context.message)
    
    def __str__(self):
        return f"[{self.context.category.value.upper()}] {self.context.message}"


class ValidationError(NLPIaCAnalyzerError):
    """Exception raised for validation errors."""
    pass


class ConfigurationError(NLPIaCAnalyzerError):
    """Exception raised for configuration-related errors."""
    pass


class ParsingError(NLPIaCAnalyzerError):
    """Exception raised for Terraform parsing errors."""
    pass


class NLPProcessingError(NLPIaCAnalyzerError):
    """Exception raised for NLP processing errors."""
    pass


class GraphProcessingError(NLPIaCAnalyzerError):
    """Exception raised for graph processing errors."""
    pass


class PathDetectionError(NLPIaCAnalyzerError):
    """Exception raised for path detection errors."""
    pass


class VisualizationError(NLPIaCAnalyzerError):
    """Exception raised for visualization errors."""
    pass


class ErrorHandler:
    """Centralized error handling and recovery system."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_history: List[ErrorContext] = []
        self.recovery_strategies: Dict[ErrorCategory, callable] = {
            ErrorCategory.INPUT_VALIDATION: self._recover_input_validation,
            ErrorCategory.CONFIGURATION: self._recover_configuration,
            ErrorCategory.PARSING: self._recover_parsing,
            ErrorCategory.NLP_PROCESSING: self._recover_nlp_processing,
            ErrorCategory.GRAPH_PROCESSING: self._recover_graph_processing,
            ErrorCategory.PATH_DETECTION: self._recover_path_detection,
            ErrorCategory.VISUALIZATION: self._recover_visualization,
        }
    
    def handle_error(self, error: Union[Exception, ErrorContext], 
                    attempt_recovery: bool = True) -> Optional[Any]:
        """
        Handle an error with optional recovery attempt.
        
        Args:
            error: Exception or ErrorContext to handle
            attempt_recovery: Whether to attempt error recovery
            
        Returns:
            Recovery result if successful, None otherwise
        """
        if isinstance(error, Exception):
            context = self._create_error_context_from_exception(error)
        else:
            context = error
        
        # Log the error
        self._log_error(context)
        
        # Store in error history
        self.error_history.append(context)
        
        # Attempt recovery if requested and error is recoverable
        if attempt_recovery and context.recoverable:
            return self._attempt_recovery(context)
        
        return None
    
    def _create_error_context_from_exception(self, error: Exception) -> ErrorContext:
        """Create ErrorContext from a generic exception."""
        # Determine category based on exception type
        category = ErrorCategory.SYSTEM_ERROR
        if isinstance(error, (FileNotFoundError, PermissionError)):
            category = ErrorCategory.IO_ERROR
        elif isinstance(error, ValueError):
            category = ErrorCategory.INPUT_VALIDATION
        elif isinstance(error, ImportError):
            category = ErrorCategory.CONFIGURATION
        
        # Determine severity
        severity = ErrorSeverity.MEDIUM
        if isinstance(error, (MemoryError, SystemError)):
            severity = ErrorSeverity.CRITICAL
        elif isinstance(error, (FileNotFoundError, ImportError)):
            severity = ErrorSeverity.HIGH
        
        return ErrorContext(
            category=category,
            severity=severity,
            message=str(error),
            details=traceback.format_exc(),
            stack_trace=traceback.format_exc(),
            recoverable=severity != ErrorSeverity.CRITICAL
        )
    
    def _log_error(self, context: ErrorContext):
        """Log error based on severity."""
        log_message = f"{context.category.value}: {context.message}"
        
        if context.details:
            log_message += f" - {context.details}"
        
        if context.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif context.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message)
        elif context.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        if context.stack_trace and context.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            self.logger.debug(f"Stack trace: {context.stack_trace}")
    
    def _attempt_recovery(self, context: ErrorContext) -> Optional[Any]:
        """Attempt to recover from an error."""
        recovery_strategy = self.recovery_strategies.get(context.category)
        if recovery_strategy:
            try:
                return recovery_strategy(context)
            except Exception as e:
                self.logger.warning(f"Recovery attempt failed: {e}")
        return None
    
    def _recover_input_validation(self, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for input validation errors."""
        self.logger.info("Attempting input validation recovery...")
        # Could implement default value substitution, user prompts, etc.
        return None
    
    def _recover_configuration(self, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for configuration errors."""
        self.logger.info("Attempting configuration recovery...")
        # Could load default configuration, prompt for missing values, etc.
        return None
    
    def _recover_parsing(self, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for parsing errors."""
        self.logger.info("Attempting parsing recovery...")
        # Could skip malformed files, use partial parsing, etc.
        return None
    
    def _recover_nlp_processing(self, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for NLP processing errors."""
        self.logger.info("Attempting NLP processing recovery...")
        # Could fall back to keyword-only analysis, use simpler models, etc.
        return None
    
    def _recover_graph_processing(self, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for graph processing errors."""
        self.logger.info("Attempting graph processing recovery...")
        # Could simplify graph, remove problematic nodes, etc.
        return None
    
    def _recover_path_detection(self, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for path detection errors."""
        self.logger.info("Attempting path detection recovery...")
        # Could use simpler algorithms, reduce search space, etc.
        return None
    
    def _recover_visualization(self, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for visualization errors."""
        self.logger.info("Attempting visualization recovery...")
        # Could generate simpler visualizations, text-only reports, etc.
        return None
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all handled errors."""
        summary = {
            'total_errors': len(self.error_history),
            'by_category': {},
            'by_severity': {},
            'recoverable_count': 0,
            'critical_errors': []
        }
        
        for error in self.error_history:
            # Count by category
            category_name = error.category.value
            summary['by_category'][category_name] = summary['by_category'].get(category_name, 0) + 1
            
            # Count by severity
            severity_name = error.severity.value
            summary['by_severity'][severity_name] = summary['by_severity'].get(severity_name, 0) + 1
            
            # Count recoverable errors
            if error.recoverable:
                summary['recoverable_count'] += 1
            
            # Track critical errors
            if error.severity == ErrorSeverity.CRITICAL:
                summary['critical_errors'].append({
                    'message': error.message,
                    'category': error.category.value,
                    'file_path': error.file_path
                })
        
        return summary


class InputValidator:
    """Comprehensive input validation utilities."""
    
    @staticmethod
    def validate_terraform_directory(directory_path: str) -> List[str]:
        """Validate Terraform directory and return list of issues."""
        issues = []
        path = Path(directory_path)
        
        if not path.exists():
            issues.append(f"Directory '{directory_path}' does not exist")
            return issues
        
        if not path.is_dir():
            issues.append(f"'{directory_path}' is not a directory")
            return issues
        
        # Check for .tf files
        tf_files = list(path.glob("*.tf"))
        if not tf_files:
            issues.append(f"No Terraform (.tf) files found in '{directory_path}'")
        
        # Check file permissions
        for tf_file in tf_files:
            if not tf_file.is_file():
                issues.append(f"'{tf_file}' is not a regular file")
            elif not tf_file.stat().st_size > 0:
                issues.append(f"'{tf_file}' is empty")
        
        return issues
    
    @staticmethod
    def validate_output_directory(directory_path: str) -> List[str]:
        """Validate output directory and return list of issues."""
        issues = []
        path = Path(directory_path)
        
        # Check if parent directory exists and is writable
        parent = path.parent
        if not parent.exists():
            issues.append(f"Parent directory '{parent}' does not exist")
        elif not parent.is_dir():
            issues.append(f"Parent path '{parent}' is not a directory")
        else:
            # Check write permissions
            try:
                test_file = parent / ".write_test"
                test_file.touch()
                test_file.unlink()
            except PermissionError:
                issues.append(f"No write permission for directory '{parent}'")
            except Exception as e:
                issues.append(f"Cannot write to directory '{parent}': {e}")
        
        return issues
    
    @staticmethod
    def validate_config_file(config_path: str) -> List[str]:
        """Validate configuration file and return list of issues."""
        issues = []
        path = Path(config_path)
        
        if not path.exists():
            issues.append(f"Configuration file '{config_path}' does not exist")
            return issues
        
        if not path.is_file():
            issues.append(f"'{config_path}' is not a regular file")
            return issues
        
        # Check file extension
        if path.suffix.lower() not in ['.json', '.yaml', '.yml']:
            issues.append(f"Configuration file must be JSON or YAML format, got '{path.suffix}'")
        
        # Try to parse the file
        try:
            if path.suffix.lower() == '.json':
                import json
                with open(path, 'r') as f:
                    json.load(f)
            else:
                try:
                    import yaml
                    with open(path, 'r') as f:
                        yaml.safe_load(f)
                except ImportError:
                    issues.append("PyYAML is required to load YAML configuration files")
        except Exception as e:
            issues.append(f"Cannot parse configuration file: {e}")
        
        return issues
    
    @staticmethod
    def validate_numeric_range(value: Union[int, float], min_val: Union[int, float], 
                             max_val: Union[int, float], name: str) -> List[str]:
        """Validate numeric value is within specified range."""
        issues = []
        
        if not isinstance(value, (int, float)):
            issues.append(f"{name} must be a number, got {type(value).__name__}")
            return issues
        
        if value < min_val:
            issues.append(f"{name} must be >= {min_val}, got {value}")
        
        if value > max_val:
            issues.append(f"{name} must be <= {max_val}, got {value}")
        
        return issues
    
    @staticmethod
    def validate_string_choices(value: str, choices: List[str], name: str) -> List[str]:
        """Validate string value is one of allowed choices."""
        issues = []
        
        if not isinstance(value, str):
            issues.append(f"{name} must be a string, got {type(value).__name__}")
            return issues
        
        if value not in choices:
            issues.append(f"{name} must be one of {choices}, got '{value}'")
        
        return issues


class TerraformValidator:
    """Specialized validator for Terraform files and configurations."""
    
    @staticmethod
    def validate_terraform_syntax(file_path: str) -> List[str]:
        """Validate Terraform file syntax."""
        issues = []
        
        try:
            import hcl2
            with open(file_path, 'r') as f:
                hcl2.load(f)
        except ImportError:
            issues.append("python-hcl2 library is required for Terraform parsing")
        except Exception as e:
            issues.append(f"Terraform syntax error in '{file_path}': {e}")
        
        return issues
    
    @staticmethod
    def validate_iam_resource_structure(resource_data: Dict[str, Any]) -> List[str]:
        """Validate IAM resource structure."""
        issues = []
        
        # Check required fields
        required_fields = ['resource_type', 'name']
        for field in required_fields:
            if field not in resource_data:
                issues.append(f"Missing required field: {field}")
        
        # Validate resource type
        if 'resource_type' in resource_data:
            valid_types = [
                'aws_iam_user', 'aws_iam_role', 'aws_iam_policy',
                'aws_iam_group', 'aws_iam_role_policy_attachment',
                'aws_iam_user_policy_attachment', 'aws_iam_group_policy_attachment'
            ]
            if resource_data['resource_type'] not in valid_types:
                issues.append(f"Invalid IAM resource type: {resource_data['resource_type']}")
        
        # Validate name format
        if 'name' in resource_data:
            name = resource_data['name']
            if not isinstance(name, str) or not name.strip():
                issues.append("Resource name must be a non-empty string")
        
        return issues


def create_error_context(category: ErrorCategory, severity: ErrorSeverity, 
                        message: str, **kwargs) -> ErrorContext:
    """Convenience function to create ErrorContext."""
    return ErrorContext(
        category=category,
        severity=severity,
        message=message,
        **kwargs
    )


def handle_terraform_parsing_error(file_path: str, error: Exception) -> ErrorContext:
    """Create error context for Terraform parsing errors."""
    suggestions = [
        "Check Terraform file syntax using 'terraform validate'",
        "Ensure all brackets and quotes are properly closed",
        "Verify resource block structure is correct"
    ]
    
    return ErrorContext(
        category=ErrorCategory.PARSING,
        severity=ErrorSeverity.HIGH,
        message=f"Failed to parse Terraform file: {error}",
        details=f"Error occurred while parsing '{file_path}'",
        suggestions=suggestions,
        file_path=file_path,
        recoverable=True
    )


def handle_nlp_model_error(model_name: str, error: Exception) -> ErrorContext:
    """Create error context for NLP model loading errors."""
    suggestions = [
        "Check internet connection for model download",
        "Verify model name is correct",
        "Try using a different model or disable NLP analysis",
        "Ensure sufficient disk space for model files"
    ]
    
    return ErrorContext(
        category=ErrorCategory.NLP_PROCESSING,
        severity=ErrorSeverity.MEDIUM,
        message=f"Failed to load NLP model '{model_name}': {error}",
        suggestions=suggestions,
        recoverable=True
    )


def handle_configuration_error(config_path: str, error: Exception) -> ErrorContext:
    """Create error context for configuration errors."""
    suggestions = [
        "Check configuration file syntax (JSON/YAML)",
        "Verify all required configuration fields are present",
        "Use default configuration if custom config is problematic",
        "Validate configuration values are within acceptable ranges"
    ]
    
    return ErrorContext(
        category=ErrorCategory.CONFIGURATION,
        severity=ErrorSeverity.HIGH,
        message=f"Configuration error: {error}",
        details=f"Error in configuration file '{config_path}'",
        suggestions=suggestions,
        file_path=config_path,
        recoverable=True
    )
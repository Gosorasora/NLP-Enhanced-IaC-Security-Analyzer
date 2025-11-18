"""
Terraform file parser for extracting IAM resources and configurations.

This module handles parsing of Terraform (.tf) files using python-hcl2
and provides error handling for malformed syntax.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import hcl2
import json

from config.settings import Config


class TerraformParseError(Exception):
    """Custom exception for Terraform parsing errors."""
    pass


class TerraformParser:
    """
    Parser for Terraform configuration files.
    
    Handles directory traversal, file discovery, and parsing of .tf files
    with comprehensive error handling and logging.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the Terraform parser.
        
        Args:
            config: Configuration object containing parser settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Supported file extensions
        self.tf_extensions = {'.tf', '.tf.json'}
        
        # Track parsing statistics
        self.stats = {
            'files_found': 0,
            'files_parsed': 0,
            'files_failed': 0,
            'resources_found': 0
        }
    
    def parse_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Parse all Terraform files in a directory recursively.
        
        Args:
            directory_path: Path to directory containing .tf files
            
        Returns:
            Dictionary containing merged parsed configuration data
            
        Raises:
            FileNotFoundError: If directory doesn't exist
            TerraformParseError: If no valid Terraform files found
        """
        dir_path = Path(directory_path)
        
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not dir_path.is_dir():
            raise ValueError(f"Path is not a directory: {directory_path}")
        
        self.logger.info(f"Parsing Terraform files in directory: {directory_path}")
        
        # Find all Terraform files
        tf_files = self._discover_terraform_files(dir_path)
        
        if not tf_files:
            raise TerraformParseError(f"No Terraform files found in directory: {directory_path}")
        
        self.stats['files_found'] = len(tf_files)
        self.logger.info(f"Found {len(tf_files)} Terraform files")
        
        # Parse all files and merge results
        merged_config = {
            'resource': {},
            'data': {},
            'variable': {},
            'output': {},
            'locals': {},
            'provider': {},
            'terraform': {},
            'module': {}
        }
        
        file_metadata = {}
        
        for tf_file in tf_files:
            try:
                self.logger.debug(f"Parsing file: {tf_file}")
                file_config = self.parse_file(str(tf_file))
                
                # Store file metadata
                file_metadata[str(tf_file)] = {
                    'path': str(tf_file),
                    'size': tf_file.stat().st_size,
                    'modified': tf_file.stat().st_mtime
                }
                
                # Merge configuration sections
                self._merge_config_sections(merged_config, file_config, str(tf_file))
                
                self.stats['files_parsed'] += 1
                
            except Exception as e:
                self.stats['files_failed'] += 1
                self.logger.error(f"Failed to parse {tf_file}: {str(e)}")
                
                if self.config.verbose:
                    self.logger.exception(f"Detailed error for {tf_file}")
                
                # Continue parsing other files unless in strict mode
                continue
        
        if self.stats['files_parsed'] == 0:
            raise TerraformParseError("No Terraform files could be successfully parsed")
        
        # Add metadata to merged config
        merged_config['_metadata'] = {
            'parsing_stats': self.stats,
            'files': file_metadata,
            'directory': str(dir_path.absolute())
        }
        
        self.logger.info(f"Successfully parsed {self.stats['files_parsed']}/{self.stats['files_found']} files")
        
        return merged_config
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a single Terraform file.
        
        Args:
            file_path: Path to .tf or .tf.json file
            
        Returns:
            Dictionary containing parsed configuration data
            
        Raises:
            FileNotFoundError: If file doesn't exist
            TerraformParseError: If file contains invalid syntax
        """
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            raise FileNotFoundError(f"Terraform file not found: {file_path}")
        
        if file_path_obj.suffix not in self.tf_extensions and not file_path.endswith('.tf.json'):
            raise ValueError(f"File is not a Terraform file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Handle different file types
            if file_path.endswith('.tf.json'):
                # Parse JSON format
                parsed_config = json.loads(content)
            else:
                # Parse HCL format
                parsed_config = hcl2.loads(content)
            
            # Add file metadata
            parsed_config['_file_info'] = {
                'path': str(file_path_obj.absolute()),
                'name': file_path_obj.name,
                'size': len(content),
                'lines': content.count('\n') + 1
            }
            
            # Extract and store comments if present
            comments = self._extract_comments(content)
            if comments:
                parsed_config['_comments'] = comments
            
            return parsed_config
            
        except json.JSONDecodeError as e:
            raise TerraformParseError(f"Invalid JSON syntax in {file_path}: {str(e)}")
        
        except Exception as e:
            raise TerraformParseError(f"Failed to parse {file_path}: {str(e)}")
    
    def _discover_terraform_files(self, directory: Path) -> List[Path]:
        """
        Recursively discover all Terraform files in a directory.
        
        Args:
            directory: Directory to search
            
        Returns:
            List of Path objects for discovered Terraform files
        """
        tf_files = []
        
        try:
            # Use rglob for recursive search
            for pattern in ['*.tf', '*.tf.json']:
                tf_files.extend(directory.rglob(pattern))
            
            # Filter out files in .terraform directories and other excluded paths
            excluded_dirs = {'.terraform', '.git', 'node_modules', '__pycache__'}
            
            filtered_files = []
            for tf_file in tf_files:
                # Check if file is in an excluded directory
                if any(excluded_dir in tf_file.parts for excluded_dir in excluded_dirs):
                    self.logger.debug(f"Skipping file in excluded directory: {tf_file}")
                    continue
                
                # Check file size (skip very large files that might not be valid TF)
                try:
                    if tf_file.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                        self.logger.warning(f"Skipping large file: {tf_file} ({tf_file.stat().st_size} bytes)")
                        continue
                except OSError:
                    continue
                
                filtered_files.append(tf_file)
            
            return sorted(filtered_files)
            
        except Exception as e:
            self.logger.error(f"Error discovering Terraform files: {str(e)}")
            return []
    
    def _merge_config_sections(self, merged_config: Dict[str, Any], 
                               file_config: Dict[str, Any], file_path: str):
        """
        Merge configuration sections from a file into the main config.
        
        Args:
            merged_config: Main configuration dictionary to merge into
            file_config: Configuration from a single file
            file_path: Path of the file being merged (for error reporting)
        """
        for section_name in ['resource', 'data', 'variable', 'output', 'locals', 'provider', 'terraform', 'module']:
            if section_name in file_config:
                section_data = file_config[section_name]
                
                if section_name not in merged_config:
                    merged_config[section_name] = {}
                
                if isinstance(section_data, dict):
                    # Handle nested resource types
                    for resource_type, resources in section_data.items():
                        if resource_type not in merged_config[section_name]:
                            merged_config[section_name][resource_type] = {}
                        
                        if isinstance(resources, dict):
                            for resource_name, resource_config in resources.items():
                                # Add file source information
                                if isinstance(resource_config, dict):
                                    resource_config['_source_file'] = file_path
                                
                                # Check for duplicates
                                if resource_name in merged_config[section_name][resource_type]:
                                    self.logger.warning(
                                        f"Duplicate {section_name}.{resource_type}.{resource_name} "
                                        f"found in {file_path}"
                                    )
                                
                                merged_config[section_name][resource_type][resource_name] = resource_config
                        else:
                            # Handle non-dict resources (shouldn't happen in normal TF)
                            merged_config[section_name][resource_type] = resources
                elif isinstance(section_data, list):
                    # Handle list-based sections
                    if section_name not in merged_config:
                        merged_config[section_name] = []
                    elif not isinstance(merged_config[section_name], list):
                        # Convert dict to list if needed
                        merged_config[section_name] = []
                    merged_config[section_name].extend(section_data)
    
    def _extract_comments(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract comments from Terraform file content.
        
        Args:
            content: Raw file content
            
        Returns:
            List of comment dictionaries with line numbers and text
        """
        comments = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped_line = line.strip()
            
            # Single-line comments
            if stripped_line.startswith('#') or stripped_line.startswith('//'):
                comment_text = stripped_line[1:].strip() if stripped_line.startswith('#') else stripped_line[2:].strip()
                comments.append({
                    'line': line_num,
                    'type': 'single',
                    'text': comment_text
                })
            
            # Inline comments (basic detection)
            elif '#' in line and not line.strip().startswith('"'):
                # Simple heuristic to detect inline comments
                # This is not perfect but covers most cases
                hash_pos = line.find('#')
                if hash_pos > 0:
                    comment_text = line[hash_pos + 1:].strip()
                    comments.append({
                        'line': line_num,
                        'type': 'inline',
                        'text': comment_text
                    })
        
        return comments
    
    def validate_syntax(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Validate Terraform syntax without full parsing.
        
        Args:
            file_path: Path to Terraform file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            self.parse_file(file_path)
            return True, None
        except Exception as e:
            return False, str(e)
    
    def get_parsing_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the parsing process.
        
        Returns:
            Dictionary containing parsing statistics
        """
        return {
            'files_discovered': self.stats['files_found'],
            'files_successfully_parsed': self.stats['files_parsed'],
            'files_failed': self.stats['files_failed'],
            'success_rate': (self.stats['files_parsed'] / max(1, self.stats['files_found'])) * 100,
            'resources_extracted': self.stats['resources_found']
        }
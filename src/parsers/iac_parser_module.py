"""
Main IaC Parser Module implementation.

This module implements the IaCParserModule interface and orchestrates
the parsing, extraction, and graph building process.
"""

import logging
from typing import Dict, List, Any, Tuple
import networkx as nx

from src.core.interfaces import IaCParserModule
from src.core.data_models import IAMResource
from config.settings import Config
from src.parsers.terraform_parser import TerraformParser
from src.parsers.resource_extractor import ResourceExtractor
from src.core.graph_builder import GraphBuilder


class IaCParserModuleImpl(IaCParserModule):
    """
    Implementation of the IaC Parser Module interface.
    
    Orchestrates the complete parsing pipeline from Terraform files
    to IAM resource graph construction.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the IaC parser module.
        
        Args:
            config: Configuration object containing parser settings
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Initialize sub-components
        self.terraform_parser = TerraformParser(config)
        self.resource_extractor = ResourceExtractor(config)
        self.graph_builder = GraphBuilder(config)
        
        # Cache for parsed data
        self._parsed_data_cache = {}
        self._resources_cache = {}
    
    def parse_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Parse all Terraform files in a directory.
        
        Args:
            directory_path: Path to directory containing .tf files
            
        Returns:
            Dictionary containing parsed Terraform configuration data
            
        Raises:
            FileNotFoundError: If directory doesn't exist
            ValueError: If no valid Terraform files found
        """
        self.logger.info(f"Parsing Terraform directory: {directory_path}")
        
        # Check cache first
        if directory_path in self._parsed_data_cache:
            self.logger.debug(f"Using cached parsed data for {directory_path}")
            return self._parsed_data_cache[directory_path]
        
        # Parse using terraform parser
        parsed_data = self.terraform_parser.parse_directory(directory_path)
        
        # Cache the result
        self._parsed_data_cache[directory_path] = parsed_data
        
        self.logger.info(f"Successfully parsed directory: {directory_path}")
        return parsed_data
    
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
        self.logger.info(f"Parsing Terraform file: {file_path}")
        
        # Parse using terraform parser
        parsed_data = self.terraform_parser.parse_file(file_path)
        
        self.logger.info(f"Successfully parsed file: {file_path}")
        return parsed_data
    
    def extract_iam_resources(self, parsed_data: Dict[str, Any]) -> List[IAMResource]:
        """
        Extract IAM resources from parsed Terraform data.
        
        Args:
            parsed_data: Dictionary containing parsed Terraform configuration
            
        Returns:
            List of IAMResource objects representing all IAM resources found
        """
        self.logger.info("Extracting IAM resources from parsed data")
        
        # Generate cache key from parsed data
        cache_key = self._generate_cache_key(parsed_data)
        
        # Check cache first
        if cache_key in self._resources_cache:
            self.logger.debug("Using cached IAM resources")
            return self._resources_cache[cache_key]
        
        # Extract using resource extractor
        resources = self.resource_extractor.extract_iam_resources(parsed_data)
        
        # Cache the result
        self._resources_cache[cache_key] = resources
        
        self.logger.info(f"Successfully extracted {len(resources)} IAM resources")
        return resources
    
    def build_graph(self, resources: List[IAMResource]) -> nx.DiGraph:
        """
        Build a directed graph from IAM resources.
        
        Args:
            resources: List of IAM resources to include in graph
            
        Returns:
            NetworkX directed graph with resources as nodes and relationships as edges
        """
        self.logger.info(f"Building graph from {len(resources)} IAM resources")
        
        # Build using graph builder
        graph = self.graph_builder.build_graph(resources)
        
        self.logger.info(
            f"Successfully built graph: {graph.number_of_nodes()} nodes, "
            f"{graph.number_of_edges()} edges"
        )
        return graph
    
    def get_resource_relationships(self, resources: List[IAMResource]) -> List[Tuple[str, str, str]]:
        """
        Identify relationships between IAM resources.
        
        Args:
            resources: List of IAM resources to analyze
            
        Returns:
            List of tuples (source_id, target_id, relationship_type)
        """
        self.logger.info(f"Identifying relationships between {len(resources)} resources")
        
        # Use graph builder to find relationships
        relationships = self.graph_builder.get_resource_relationships(resources)
        
        self.logger.info(f"Found {len(relationships)} relationships")
        return relationships
    
    def parse_and_extract(self, directory_path: str) -> Tuple[Dict[str, Any], List[IAMResource]]:
        """
        Convenience method to parse directory and extract resources in one call.
        
        Args:
            directory_path: Path to directory containing .tf files
            
        Returns:
            Tuple of (parsed_data, iam_resources)
        """
        self.logger.info(f"Parsing and extracting from directory: {directory_path}")
        
        # Parse directory
        parsed_data = self.parse_directory(directory_path)
        
        # Extract IAM resources
        resources = self.extract_iam_resources(parsed_data)
        
        return parsed_data, resources
    
    def parse_extract_and_build(self, directory_path: str) -> Tuple[List[IAMResource], nx.DiGraph]:
        """
        Convenience method to perform complete pipeline: parse, extract, and build graph.
        
        Args:
            directory_path: Path to directory containing .tf files
            
        Returns:
            Tuple of (iam_resources, graph)
        """
        self.logger.info(f"Complete pipeline for directory: {directory_path}")
        
        # Parse and extract
        parsed_data, resources = self.parse_and_extract(directory_path)
        
        # Build graph
        graph = self.build_graph(resources)
        
        self.logger.info("Complete pipeline finished successfully")
        return resources, graph
    
    def validate_terraform_syntax(self, file_path: str) -> Tuple[bool, str]:
        """
        Validate Terraform syntax for a file.
        
        Args:
            file_path: Path to Terraform file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        return self.terraform_parser.validate_syntax(file_path)
    
    def get_parsing_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about the parsing process.
        
        Returns:
            Dictionary containing parsing, extraction, and graph statistics
        """
        stats = {
            'terraform_parsing': self.terraform_parser.get_parsing_statistics(),
            'resource_extraction': self.resource_extractor.get_extraction_statistics(),
            'graph_building': self.graph_builder.get_graph_statistics()
        }
        
        # Add cache statistics
        stats['cache'] = {
            'parsed_data_entries': len(self._parsed_data_cache),
            'resource_cache_entries': len(self._resources_cache)
        }
        
        return stats
    
    def clear_cache(self):
        """Clear all cached data."""
        self._parsed_data_cache.clear()
        self._resources_cache.clear()
        self.logger.info("Cleared all cached data")
    
    def _generate_cache_key(self, parsed_data: Dict[str, Any]) -> str:
        """
        Generate a cache key from parsed data.
        
        Args:
            parsed_data: Parsed Terraform data
            
        Returns:
            String cache key
        """
        # Simple hash-based cache key
        # In production, you might want a more sophisticated approach
        import hashlib
        import json
        
        try:
            # Create a simplified representation for hashing
            cache_data = {
                'resource_count': len(parsed_data.get('resource', {})),
                'data_count': len(parsed_data.get('data', {})),
                'files': list(parsed_data.get('_metadata', {}).get('files', {}).keys())
            }
            
            cache_str = json.dumps(cache_data, sort_keys=True)
            return hashlib.md5(cache_str.encode()).hexdigest()
        
        except Exception:
            # Fallback to timestamp-based key
            import time
            return f"cache_{int(time.time())}"
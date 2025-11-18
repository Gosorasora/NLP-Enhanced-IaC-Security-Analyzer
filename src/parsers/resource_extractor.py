"""
IAM resource extraction logic for Terraform configurations.

This module identifies and extracts IAM resources from parsed Terraform data,
including resource attributes, policies, and relationships.
"""

import json
import logging
import os
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

from src.core.data_models import IAMResource, ResourceType
from config.settings import Config


class ResourceExtractor:
    """
    Extracts IAM resources from parsed Terraform configuration data.
    
    Handles identification of IAM resources, extraction of attributes,
    policy parsing, and relationship detection.
    """
    
    # Supported IAM resource types
    IAM_RESOURCE_TYPES = {
        'aws_iam_user': ResourceType.USER,
        'aws_iam_role': ResourceType.ROLE,
        'aws_iam_policy': ResourceType.POLICY,
        'aws_iam_group': ResourceType.GROUP,
        'aws_iam_instance_profile': ResourceType.INSTANCE_PROFILE,
        'aws_iam_access_key': ResourceType.ACCESS_KEY,
        'aws_iam_role_policy': ResourceType.ROLE_POLICY,
        'aws_iam_user_policy': ResourceType.USER_POLICY,
        'aws_iam_group_policy': ResourceType.GROUP_POLICY,
        'aws_iam_policy_attachment': ResourceType.POLICY_ATTACHMENT,
        'aws_iam_role_policy_attachment': ResourceType.ROLE_POLICY_ATTACHMENT,
        'aws_iam_user_policy_attachment': ResourceType.USER_POLICY_ATTACHMENT,
        'aws_iam_group_policy_attachment': ResourceType.GROUP_POLICY_ATTACHMENT
    }
    
    def __init__(self, config: Config):
        """
        Initialize the resource extractor.
        
        Args:
            config: Configuration object containing extraction settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Statistics tracking
        self.extraction_stats = {
            'total_resources': 0,
            'iam_resources': 0,
            'resources_by_type': {},
            'resources_with_policies': 0,
            'resources_with_comments': 0
        }
    
    def extract_iam_resources(self, parsed_data: Dict[str, Any]) -> List[IAMResource]:
        """
        Extract all IAM resources from parsed Terraform data.
        
        Args:
            parsed_data: Dictionary containing parsed Terraform configuration
            
        Returns:
            List of IAMResource objects representing all IAM resources found
        """
        self.logger.info("Extracting IAM resources from parsed Terraform data")
        
        resources = []
        
        # Extract from resource section
        if 'resource' in parsed_data:
            self.logger.debug(f"Resource section type: {type(parsed_data['resource'])}")
        self.logger.debug(f"Resource section content: {parsed_data['resource']}")
        resources.extend(self._extract_from_resource_section(parsed_data['resource']))
        
        # Extract from data section (data sources)
        if 'data' in parsed_data:
            resources.extend(self._extract_from_data_section(parsed_data['data']))
        
        # Update statistics
        self.extraction_stats['iam_resources'] = len(resources)
        
        self.logger.info(f"Extracted {len(resources)} IAM resources")
        
        return resources
    
    def _extract_from_resource_section(self, resource_section: Dict[str, Any]) -> List[IAMResource]:
        """
        Extract IAM resources from the resource section.
        
        Args:
            resource_section: Resource section from parsed Terraform data
            
        Returns:
            List of IAMResource objects
        """
        resources = []
        
        # Handle both dict and list formats
        if isinstance(resource_section, dict):
            resource_items = resource_section.items()
        elif isinstance(resource_section, list):
            # Process list of resource dictionaries
            self.logger.debug(f"Processing resource section as list with {len(resource_section)} items")
            for resource_dict in resource_section:
                if isinstance(resource_dict, dict):
                    for resource_type, resource_instances in resource_dict.items():
                        if resource_type in self.IAM_RESOURCE_TYPES:
                            self.logger.debug(f"Processing {resource_type} resources from list")
                            
                            if not isinstance(resource_instances, dict):
                                self.logger.warning(f"Unexpected format for {resource_type}: {type(resource_instances)}")
                                continue
                            
                            for resource_name, resource_config in resource_instances.items():
                                try:
                                    iam_resource = self._create_iam_resource(
                                        resource_type, resource_name, resource_config
                                    )
                                    if iam_resource:
                                        resources.append(iam_resource)
                                        self.logger.debug(f"Created IAM resource: {resource_type}.{resource_name}")
                                        
                                        # Update statistics
                                        if resource_type not in self.extraction_stats['resources_by_type']:
                                            self.extraction_stats['resources_by_type'][resource_type] = 0
                                        self.extraction_stats['resources_by_type'][resource_type] += 1
                                        
                                except Exception as e:
                                    self.logger.error(f"Failed to create IAM resource {resource_type}.{resource_name}: {e}")
            return resources
        else:
            self.logger.error(f"Unexpected resource section format: {type(resource_section)}")
            return resources
            
        for resource_type, resource_instances in resource_items:
            if resource_type in self.IAM_RESOURCE_TYPES:
                self.logger.debug(f"Processing {resource_type} resources")
                
                if not isinstance(resource_instances, dict):
                    self.logger.warning(f"Unexpected format for {resource_type}: {type(resource_instances)}")
                    continue
                
                for resource_name, resource_config in resource_instances.items():
                    try:
                        iam_resource = self._create_iam_resource(
                            resource_type, resource_name, resource_config
                        )
                        resources.append(iam_resource)
                        
                        # Update statistics
                        if resource_type not in self.extraction_stats['resources_by_type']:
                            self.extraction_stats['resources_by_type'][resource_type] = 0
                        self.extraction_stats['resources_by_type'][resource_type] += 1
                        
                    except Exception as e:
                        self.logger.error(f"Failed to extract {resource_type}.{resource_name}: {str(e)}")
                        if self.config.verbose:
                            self.logger.exception(f"Detailed error for {resource_type}.{resource_name}")
        
        return resources
    
    def _extract_from_data_section(self, data_section: Dict[str, Any]) -> List[IAMResource]:
        """
        Extract IAM resources from the data section (data sources).
        
        Args:
            data_section: Data section from parsed Terraform data
            
        Returns:
            List of IAMResource objects
        """
        resources = []
        
        # Data sources that reference IAM resources
        iam_data_sources = {
            'aws_iam_user', 'aws_iam_role', 'aws_iam_policy', 'aws_iam_group',
            'aws_iam_policy_document', 'aws_iam_instance_profile'
        }
        
        # Handle both dict and list formats
        if isinstance(data_section, list):
            # Process each data block in the list
            for data_block in data_section:
                if isinstance(data_block, dict):
                    for data_type, data_instances in data_block.items():
                        self._process_data_type(data_type, data_instances, iam_data_sources, resources)
        elif isinstance(data_section, dict):
            for data_type, data_instances in data_section.items():
                self._process_data_type(data_type, data_instances, iam_data_sources, resources)
        
        return resources
    
    def _process_data_type(self, data_type: str, data_instances: Any, iam_data_sources: set, resources: List[IAMResource]):
        """Process a specific data type."""
        if data_type in iam_data_sources:
            self.logger.debug(f"Processing data source {data_type}")
            
            if not isinstance(data_instances, dict):
                return
            
            for data_name, data_config in data_instances.items():
                try:
                    # Create IAM resource from data source
                    # Note: Data sources are references to existing resources
                    iam_resource = self._create_iam_resource_from_data(
                        data_type, data_name, data_config
                    )
                    if iam_resource:
                        resources.append(iam_resource)
                        
                except Exception as e:
                    self.logger.error(f"Failed to extract data.{data_type}.{data_name}: {str(e)}")
    
    def _create_iam_resource(self, resource_type: str, resource_name: str, 
                             resource_config: Dict[str, Any]) -> IAMResource:
        """
        Create an IAMResource object from Terraform resource configuration.
        
        Args:
            resource_type: Terraform resource type (e.g., 'aws_iam_user')
            resource_name: Resource name from Terraform
            resource_config: Resource configuration dictionary
            
        Returns:
            IAMResource object
        """
        # Create terraform address
        terraform_address = f"{resource_type}.{resource_name}"
        
        # Extract basic attributes
        attributes = dict(resource_config)
        
        # Remove metadata fields
        source_file = attributes.pop('_source_file', None)
        
        # Extract ARN if present
        arn = self._extract_arn(resource_type, attributes)
        
        # Extract tags
        tags = self._extract_tags(attributes)
        
        # Extract comments from source file if available
        comments = self._extract_resource_comments(source_file, terraform_address)
        
        # Extract policy information
        inline_policies = self._extract_inline_policies(resource_type, attributes)
        attached_policies = self._extract_attached_policies(resource_type, attributes)
        assume_role_policy = self._extract_assume_role_policy(resource_type, attributes)
        
        # Extract trust relationships
        trust_relationships = self._extract_trust_relationships(assume_role_policy)
        
        # Get file location information
        file_path, line_number = self._get_file_location(source_file, terraform_address)
        
        # Create IAMResource object
        iam_resource = IAMResource(
            resource_type=self.IAM_RESOURCE_TYPES[resource_type],
            name=resource_name,
            terraform_address=terraform_address,
            attributes=attributes,
            arn=arn,
            tags=tags,
            comments=comments,
            inline_policies=inline_policies,
            attached_policies=attached_policies,
            assume_role_policy=assume_role_policy,
            trust_relationships=trust_relationships,
            file_path=file_path,
            line_number=line_number
        )
        
        # Update statistics
        if inline_policies or attached_policies or assume_role_policy:
            self.extraction_stats['resources_with_policies'] += 1
        
        if comments:
            self.extraction_stats['resources_with_comments'] += 1
        
        return iam_resource
    
    def _create_iam_resource_from_data(self, data_type: str, data_name: str,
                                       data_config: Dict[str, Any]) -> Optional[IAMResource]:
        """
        Create an IAMResource object from Terraform data source.
        
        Args:
            data_type: Terraform data source type
            data_name: Data source name
            data_config: Data source configuration
            
        Returns:
            IAMResource object or None if not applicable
        """
        # Map data source types to resource types
        data_to_resource_mapping = {
            'aws_iam_user': 'aws_iam_user',
            'aws_iam_role': 'aws_iam_role',
            'aws_iam_policy': 'aws_iam_policy',
            'aws_iam_group': 'aws_iam_group',
            'aws_iam_instance_profile': 'aws_iam_instance_profile'
        }
        
        if data_type not in data_to_resource_mapping:
            return None
        
        resource_type = data_to_resource_mapping[data_type]
        
        # Create resource with limited information (data sources are references)
        terraform_address = f"data.{data_type}.{data_name}"
        
        attributes = dict(data_config)
        source_file = attributes.pop('_source_file', None)
        
        return IAMResource(
            resource_type=self.IAM_RESOURCE_TYPES[resource_type],
            name=data_name,
            terraform_address=terraform_address,
            attributes=attributes,
            file_path=source_file
        )
    
    def _extract_arn(self, resource_type: str, attributes: Dict[str, Any]) -> Optional[str]:
        """Extract ARN from resource attributes."""
        # ARN might be explicitly set or computed
        return attributes.get('arn')
    
    def _extract_tags(self, attributes: Dict[str, Any]) -> Dict[str, str]:
        """Extract tags from resource attributes."""
        tags = attributes.get('tags', {})
        if isinstance(tags, dict):
            # Convert all values to strings
            return {k: str(v) for k, v in tags.items()}
        return {}
    
    def _extract_resource_comments(self, source_file: Optional[str], 
                                   terraform_address: str) -> List[str]:
        """Extract comments associated with a specific resource."""
        comments = []
        
        if not source_file or not os.path.exists(source_file):
            return comments
        
        try:
            with open(source_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Look for comments near the resource definition
            resource_name = terraform_address.split('.')[-1]
            
            for i, line in enumerate(lines):
                # Check if this line contains the resource definition
                if resource_name in line and ('resource' in line or 'data' in line):
                    # Look for comments in the lines above and below
                    start_idx = max(0, i - 3)
                    end_idx = min(len(lines), i + 10)
                    
                    for j in range(start_idx, end_idx):
                        comment_line = lines[j].strip()
                        if comment_line.startswith('#'):
                            comment_text = comment_line[1:].strip()
                            if comment_text and comment_text not in comments:
                                comments.append(comment_text)
                    break
                    
        except Exception as e:
            self.logger.debug(f"Failed to extract comments from {source_file}: {e}")
        
        return comments
    
    def _extract_inline_policies(self, resource_type: str, 
                                 attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract inline policies from resource attributes."""
        inline_policies = []
        
        # Different resource types have different policy attributes
        policy_attributes = {
            'aws_iam_role_policy': ['policy'],
            'aws_iam_user_policy': ['policy'],
            'aws_iam_group_policy': ['policy'],
            'aws_iam_role': ['inline_policy'],
            'aws_iam_user': ['inline_policy'],
            'aws_iam_group': ['inline_policy']
        }
        
        if resource_type in policy_attributes:
            for attr_name in policy_attributes[resource_type]:
                if attr_name in attributes:
                    policy_data = attributes[attr_name]
                    
                    if isinstance(policy_data, str):
                        # Parse JSON policy
                        try:
                            parsed_policy = json.loads(policy_data)
                            inline_policies.append(parsed_policy)
                        except json.JSONDecodeError:
                            self.logger.warning(f"Failed to parse policy JSON in {attr_name}")
                    
                    elif isinstance(policy_data, dict):
                        inline_policies.append(policy_data)
                    
                    elif isinstance(policy_data, list):
                        # Multiple inline policies
                        for policy in policy_data:
                            if isinstance(policy, dict) and 'policy' in policy:
                                policy_content = policy['policy']
                                if isinstance(policy_content, str):
                                    try:
                                        parsed_policy = json.loads(policy_content)
                                        inline_policies.append(parsed_policy)
                                    except json.JSONDecodeError:
                                        pass
                                elif isinstance(policy_content, dict):
                                    inline_policies.append(policy_content)
        
        return inline_policies
    
    def _extract_attached_policies(self, resource_type: str, 
                                   attributes: Dict[str, Any]) -> List[str]:
        """Extract attached policy ARNs from resource attributes."""
        attached_policies = []
        
        # Policy attachment attributes
        attachment_attributes = {
            'aws_iam_role': ['managed_policy_arns'],
            'aws_iam_user': ['managed_policy_arns'],
            'aws_iam_group': ['managed_policy_arns'],
            'aws_iam_policy_attachment': ['policy_arn'],
            'aws_iam_role_policy_attachment': ['policy_arn'],
            'aws_iam_user_policy_attachment': ['policy_arn'],
            'aws_iam_group_policy_attachment': ['policy_arn']
        }
        
        if resource_type in attachment_attributes:
            for attr_name in attachment_attributes[resource_type]:
                if attr_name in attributes:
                    policy_data = attributes[attr_name]
                    
                    if isinstance(policy_data, str):
                        attached_policies.append(policy_data)
                    elif isinstance(policy_data, list):
                        attached_policies.extend([str(p) for p in policy_data])
        
        return attached_policies
    
    def _extract_assume_role_policy(self, resource_type: str, 
                                    attributes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract assume role policy from role attributes."""
        if resource_type != 'aws_iam_role':
            return None
        
        assume_role_policy = attributes.get('assume_role_policy')
        
        if isinstance(assume_role_policy, str):
            try:
                return json.loads(assume_role_policy)
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse assume_role_policy JSON")
                return None
        elif isinstance(assume_role_policy, dict):
            return assume_role_policy
        
        return None
    
    def _extract_trust_relationships(self, assume_role_policy: Optional[Dict[str, Any]]) -> List[str]:
        """Extract trust relationships from assume role policy."""
        trust_relationships = []
        
        if not assume_role_policy:
            return trust_relationships
        
        statements = assume_role_policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            
            effect = statement.get('Effect', '').lower()
            if effect != 'allow':
                continue
            
            principal = statement.get('Principal', {})
            if isinstance(principal, dict):
                # Extract service principals
                if 'Service' in principal:
                    services = principal['Service']
                    if isinstance(services, str):
                        trust_relationships.append(services)
                    elif isinstance(services, list):
                        trust_relationships.extend(services)
                
                # Extract AWS account principals
                if 'AWS' in principal:
                    aws_principals = principal['AWS']
                    if isinstance(aws_principals, str):
                        trust_relationships.append(aws_principals)
                    elif isinstance(aws_principals, list):
                        trust_relationships.extend(aws_principals)
            
            elif isinstance(principal, str):
                trust_relationships.append(principal)
        
        return trust_relationships
    
    def _get_file_location(self, source_file: Optional[str], 
                           terraform_address: str) -> Tuple[Optional[str], Optional[int]]:
        """Get file path and line number for a resource."""
        if not source_file or not os.path.exists(source_file):
            return source_file, None
        
        try:
            with open(source_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            resource_name = terraform_address.split('.')[-1]
            
            for i, line in enumerate(lines):
                if resource_name in line and ('resource' in line or 'data' in line):
                    return source_file, i + 1  # Line numbers are 1-based
                    
        except Exception as e:
            self.logger.debug(f"Failed to get line number from {source_file}: {e}")
        
        return source_file, None
    
    def get_extraction_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the resource extraction process.
        
        Returns:
            Dictionary containing extraction statistics
        """
        return {
            'total_iam_resources': self.extraction_stats['iam_resources'],
            'resources_by_type': self.extraction_stats['resources_by_type'],
            'resources_with_policies': self.extraction_stats['resources_with_policies'],
            'resources_with_comments': self.extraction_stats['resources_with_comments'],
            'policy_coverage': (
                self.extraction_stats['resources_with_policies'] / 
                max(1, self.extraction_stats['iam_resources'])
            ) * 100
        }
    
    def validate_resource_configuration(self, resource: IAMResource) -> List[str]:
        """
        Validate IAM resource configuration and return list of issues.
        
        Args:
            resource: IAMResource to validate
            
        Returns:
            List of validation error/warning messages
        """
        issues = []
        
        # Check for required attributes based on resource type
        required_attrs = {
            ResourceType.USER: ['name'],
            ResourceType.ROLE: ['name'],
            ResourceType.POLICY: ['name'],
            ResourceType.GROUP: ['name']
        }
        
        if resource.resource_type in required_attrs:
            for attr in required_attrs[resource.resource_type]:
                if attr not in resource.attributes or not resource.attributes[attr]:
                    issues.append(f"Missing required attribute: {attr}")
        
        # Check for potential security issues
        if resource.has_wildcard_permissions():
            issues.append("Resource has wildcard permissions (*) which may be overly permissive")
        
        # Check for missing descriptions
        if not resource.description:
            issues.append("Resource lacks description or comments")
        
        # Check for suspicious naming patterns
        suspicious_patterns = ['temp', 'test', 'debug', 'admin', 'root']
        resource_name = resource.display_name.lower()
        
        for pattern in suspicious_patterns:
            if pattern in resource_name:
                issues.append(f"Resource name contains potentially risky keyword: {pattern}")
        
        return issues
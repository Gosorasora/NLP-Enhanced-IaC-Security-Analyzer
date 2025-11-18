"""
Graph construction functionality for IAM resources.

This module builds directed graphs from IAM resources using NetworkX,
creating nodes for resources and edges for permission relationships.
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple, Set
import networkx as nx

from src.core.data_models import IAMResource, ResourceType
from config.settings import Config


class GraphBuilder:
    """
    Builds directed graphs from IAM resources.
    
    Creates NetworkX directed graphs with IAM resources as nodes and
    permission relationships as edges, including role assumptions,
    policy attachments, and other IAM relationships.
    """
    
    # Relationship types for edges
    RELATIONSHIP_TYPES = {
        'ASSUME_ROLE': 'assume_role',
        'POLICY_ATTACHMENT': 'policy_attachment',
        'INLINE_POLICY': 'inline_policy',
        'PASS_ROLE': 'pass_role',
        'GROUP_MEMBERSHIP': 'group_membership',
        'INSTANCE_PROFILE': 'instance_profile',
        'TRUST_RELATIONSHIP': 'trust_relationship'
    }
    
    def __init__(self, config: Config):
        """
        Initialize the graph builder.
        
        Args:
            config: Configuration object containing graph building settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Statistics tracking
        self.graph_stats = {
            'nodes_created': 0,
            'edges_created': 0,
            'relationships_by_type': {},
            'isolated_nodes': 0
        }
    
    def build_graph(self, resources: List[IAMResource]) -> nx.DiGraph:
        """
        Build a directed graph from IAM resources.
        
        Args:
            resources: List of IAM resources to include in graph
            
        Returns:
            NetworkX directed graph with resources as nodes and relationships as edges
        """
        self.logger.info(f"Building graph from {len(resources)} IAM resources")
        
        # Create directed graph
        graph = nx.DiGraph()
        
        # Add nodes for all resources
        self._add_resource_nodes(graph, resources)
        
        # Add edges for relationships
        self._add_relationship_edges(graph, resources)
        
        # Calculate and add graph metrics
        self._add_graph_metrics(graph)
        
        # Update statistics
        self.graph_stats['nodes_created'] = graph.number_of_nodes()
        self.graph_stats['edges_created'] = graph.number_of_edges()
        self.graph_stats['isolated_nodes'] = len(list(nx.isolates(graph)))
        
        self.logger.info(
            f"Graph built: {graph.number_of_nodes()} nodes, "
            f"{graph.number_of_edges()} edges"
        )
        
        return graph
    
    def _add_resource_nodes(self, graph: nx.DiGraph, resources: List[IAMResource]):
        """
        Add nodes to the graph for each IAM resource.
        
        Args:
            graph: NetworkX graph to add nodes to
            resources: List of IAM resources
        """
        for resource in resources:
            node_id = resource.terraform_address
            
            # Node attributes (해시 가능한 타입만 사용)
            node_attrs = {
                'resource_type': resource.resource_type.value,
                'name': resource.name,
                'display_name': resource.display_name,
                'description': resource.description,
                'arn': resource.arn,
                'file_path': resource.file_path,
                'line_number': resource.line_number,
                'has_wildcard_permissions': resource.has_wildcard_permissions(),
                'text_content': resource.get_text_content(),
                # 리스트/딕셔너리는 문자열로 변환하거나 별도 저장
                'tags_str': str(resource.tags) if resource.tags else '',
                'attached_policies_count': len(resource.attached_policies) if resource.attached_policies else 0,
                'inline_policies_count': len(resource.inline_policies) if resource.inline_policies else 0,
                'trust_relationships_count': len(resource.trust_relationships) if resource.trust_relationships else 0,
                'comments_str': ' '.join(resource.comments) if resource.comments else ''
            }
            
            # 복잡한 데이터는 별도로 저장 (그래프 객체에 직접 저장)
            if not hasattr(graph, '_resource_data'):
                graph._resource_data = {}
            
            graph._resource_data[node_id] = {
                'attributes': resource.attributes,
                'inline_policies': resource.inline_policies,
                'attached_policies': resource.attached_policies,
                'assume_role_policy': resource.assume_role_policy,
                'trust_relationships': resource.trust_relationships,
                'tags': resource.tags,
                'comments': resource.comments
            }
            
            # Add visual attributes for graph rendering
            node_attrs.update(self._get_visual_attributes(resource))
            
            graph.add_node(node_id, **node_attrs)
            
            self.logger.debug(f"Added node: {node_id} ({resource.resource_type.value})")
    
    def _add_relationship_edges(self, graph: nx.DiGraph, resources: List[IAMResource]):
        """
        Add edges to the graph for relationships between resources.
        
        Args:
            graph: NetworkX graph to add edges to
            resources: List of IAM resources
        """
        # Get all relationships
        relationships = self.get_resource_relationships(resources)
        
        for source_id, target_id, relationship_type in relationships:
            if source_id in graph.nodes and target_id in graph.nodes:
                # Edge attributes
                edge_attrs = {
                    'relationship_type': relationship_type,
                    'weight': self._calculate_edge_weight(relationship_type),
                    'label': relationship_type.replace('_', ' ').title()
                }
                
                # Add visual attributes for edge rendering
                edge_attrs.update(self._get_edge_visual_attributes(relationship_type))
                
                graph.add_edge(source_id, target_id, **edge_attrs)
                
                # Update statistics
                if relationship_type not in self.graph_stats['relationships_by_type']:
                    self.graph_stats['relationships_by_type'][relationship_type] = 0
                self.graph_stats['relationships_by_type'][relationship_type] += 1
                
                self.logger.debug(f"Added edge: {source_id} -> {target_id} ({relationship_type})")
            else:
                self.logger.warning(
                    f"Skipping edge {source_id} -> {target_id}: missing nodes"
                )
    
    def get_resource_relationships(self, resources: List[IAMResource]) -> List[Tuple[str, str, str]]:
        """
        Identify relationships between IAM resources.
        
        Args:
            resources: List of IAM resources to analyze
            
        Returns:
            List of tuples (source_id, target_id, relationship_type)
        """
        relationships = []
        
        # Create lookup maps for efficient searching
        resource_map = {r.terraform_address: r for r in resources}
        name_to_address = {}
        
        for resource in resources:
            # Map display names and resource names to addresses
            if resource.display_name:
                name_to_address[str(resource.display_name)] = resource.terraform_address
            if resource.name:
                # name이 리스트일 수 있으므로 안전하게 처리
                if isinstance(resource.name, str):
                    name_to_address[resource.name] = resource.terraform_address
                elif isinstance(resource.name, list) and resource.name:
                    # 리스트의 첫 번째 요소를 사용
                    name_to_address[str(resource.name[0])] = resource.terraform_address
        
        # Find different types of relationships
        relationships.extend(self._find_simple_policy_attachments(resources))
        relationships.extend(self._find_assume_role_relationships(resources, resource_map))
        relationships.extend(self._find_policy_attachment_relationships(resources, resource_map, name_to_address))
        relationships.extend(self._find_inline_policy_relationships(resources, resource_map))
        relationships.extend(self._find_pass_role_relationships(resources, resource_map, name_to_address))
        relationships.extend(self._find_group_membership_relationships(resources, resource_map, name_to_address))
        relationships.extend(self._find_instance_profile_relationships(resources, resource_map, name_to_address))
        relationships.extend(self._find_trust_relationships(resources, resource_map))
        
        self.logger.info(f"Found {len(relationships)} relationships between resources")
        
        return relationships
    
    def _find_simple_policy_attachments(self, resources: List[IAMResource]) -> List[Tuple[str, str, str]]:
        """Find simple policy attachment relationships based on resource names."""
        relationships = []
        
        # Create lookup maps
        users = {r.terraform_address: r for r in resources if r.resource_type == ResourceType.USER}
        roles = {r.terraform_address: r for r in resources if r.resource_type == ResourceType.ROLE}
        policies = {r.terraform_address: r for r in resources if r.resource_type == ResourceType.POLICY}
        
        # Find policy attachments
        for resource in resources:
            if resource.resource_type in [
                ResourceType.USER_POLICY_ATTACHMENT,
                ResourceType.ROLE_POLICY_ATTACHMENT,
                ResourceType.POLICY_ATTACHMENT
            ]:
                # Extract user/role and policy from attributes
                user_ref = None
                role_ref = None
                policy_ref = None
                
                # Check attributes for references
                for key, value in resource.attributes.items():
                    if key in ['user'] and isinstance(value, list) and value:
                        user_ref = str(value[0])
                    elif key in ['role'] and isinstance(value, list) and value:
                        role_ref = str(value[0])
                    elif key in ['policy_arn'] and isinstance(value, list) and value:
                        policy_ref = str(value[0])
                
                # Find matching resources and create relationships
                if user_ref:
                    # Find user by name reference
                    for user_addr, user_res in users.items():
                        user_name = user_res.name
                        if isinstance(user_name, list) and user_name:
                            user_name = str(user_name[0])
                        elif isinstance(user_name, str):
                            user_name = str(user_name)
                        
                        if user_ref.endswith(user_name) or user_name in user_ref:
                            relationships.append((user_addr, resource.terraform_address, "ATTACHED_TO"))
                            if policy_ref and not policy_ref.startswith('arn:aws:iam::aws:policy/'):
                                # Custom policy
                                for policy_addr, policy_res in policies.items():
                                    if policy_ref.endswith(policy_res.name) or policy_res.name in policy_ref:
                                        relationships.append((resource.terraform_address, policy_addr, "USES_POLICY"))
                            break
                
                if role_ref:
                    # Find role by name reference
                    for role_addr, role_res in roles.items():
                        role_name = role_res.name
                        if isinstance(role_name, list) and role_name:
                            role_name = str(role_name[0])
                        elif isinstance(role_name, str):
                            role_name = str(role_name)
                        
                        if role_ref.endswith(role_name) or role_name in role_ref:
                            relationships.append((role_addr, resource.terraform_address, "ATTACHED_TO"))
                            if policy_ref and not policy_ref.startswith('arn:aws:iam::aws:policy/'):
                                # Custom policy
                                for policy_addr, policy_res in policies.items():
                                    if policy_ref.endswith(policy_res.name) or policy_res.name in policy_ref:
                                        relationships.append((resource.terraform_address, policy_addr, "USES_POLICY"))
                            break
        
        self.logger.info(f"Found {len(relationships)} simple policy attachment relationships")
        return relationships
    
    def _find_assume_role_relationships(self, resources: List[IAMResource], 
                                        resource_map: Dict[str, IAMResource]) -> List[Tuple[str, str, str]]:
        """Find assume role relationships."""
        relationships = []
        
        for resource in resources:
            if resource.resource_type == ResourceType.ROLE and resource.assume_role_policy:
                # Find principals that can assume this role
                principals = self._extract_principals_from_policy(resource.assume_role_policy)
                
                for principal in principals:
                    # Try to find matching resources
                    principal_resource = self._find_resource_by_principal(principal, resources)
                    if principal_resource:
                        relationships.append((
                            principal_resource.terraform_address,
                            resource.terraform_address,
                            self.RELATIONSHIP_TYPES['ASSUME_ROLE']
                        ))
        
        return relationships
    
    def _find_policy_attachment_relationships(self, resources: List[IAMResource],
                                              resource_map: Dict[str, IAMResource],
                                              name_to_address: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """Find policy attachment relationships."""
        relationships = []
        
        # Find policy attachment resources
        for resource in resources:
            if resource.resource_type in [
                ResourceType.POLICY_ATTACHMENT,
                ResourceType.ROLE_POLICY_ATTACHMENT,
                ResourceType.USER_POLICY_ATTACHMENT,
                ResourceType.GROUP_POLICY_ATTACHMENT
            ]:
                # Get policy and target from attributes
                policy_arn = resource.attributes.get('policy_arn')
                target_names = []
                
                # Extract target resource names based on attachment type
                if resource.resource_type == ResourceType.ROLE_POLICY_ATTACHMENT:
                    target_names.extend(resource.attributes.get('roles', []))
                elif resource.resource_type == ResourceType.USER_POLICY_ATTACHMENT:
                    target_names.extend(resource.attributes.get('users', []))
                elif resource.resource_type == ResourceType.GROUP_POLICY_ATTACHMENT:
                    target_names.extend(resource.attributes.get('groups', []))
                else:  # Generic policy attachment
                    target_names.extend(resource.attributes.get('roles', []))
                    target_names.extend(resource.attributes.get('users', []))
                    target_names.extend(resource.attributes.get('groups', []))
                
                # Find policy resource
                policy_resource = self._find_resource_by_arn_or_name(policy_arn, resources)
                
                # Create relationships
                for target_name in target_names:
                    target_address = name_to_address.get(target_name)
                    if target_address and policy_resource:
                        relationships.append((
                            policy_resource.terraform_address,
                            target_address,
                            self.RELATIONSHIP_TYPES['POLICY_ATTACHMENT']
                        ))
            
            # Also check managed_policy_arns in roles/users/groups
            elif resource.attached_policies:
                for policy_arn in resource.attached_policies:
                    policy_resource = self._find_resource_by_arn_or_name(policy_arn, resources)
                    if policy_resource:
                        relationships.append((
                            policy_resource.terraform_address,
                            resource.terraform_address,
                            self.RELATIONSHIP_TYPES['POLICY_ATTACHMENT']
                        ))
        
        return relationships
    
    def _find_inline_policy_relationships(self, resources: List[IAMResource],
                                          resource_map: Dict[str, IAMResource]) -> List[Tuple[str, str, str]]:
        """Find inline policy relationships."""
        relationships = []
        
        for resource in resources:
            if resource.resource_type in [
                ResourceType.ROLE_POLICY,
                ResourceType.USER_POLICY,
                ResourceType.GROUP_POLICY
            ]:
                # Find the target resource (role, user, or group)
                target_name = None
                
                if resource.resource_type == ResourceType.ROLE_POLICY:
                    target_name = resource.attributes.get('role')
                elif resource.resource_type == ResourceType.USER_POLICY:
                    target_name = resource.attributes.get('user')
                elif resource.resource_type == ResourceType.GROUP_POLICY:
                    target_name = resource.attributes.get('group')
                
                if target_name:
                    # Find target resource by name
                    target_resource = self._find_resource_by_name(target_name, resources)
                    if target_resource:
                        relationships.append((
                            resource.terraform_address,
                            target_resource.terraform_address,
                            self.RELATIONSHIP_TYPES['INLINE_POLICY']
                        ))
        
        return relationships
    
    def _find_pass_role_relationships(self, resources: List[IAMResource],
                                      resource_map: Dict[str, IAMResource],
                                      name_to_address: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """Find iam:PassRole relationships in policies."""
        relationships = []
        
        for resource in resources:
            # Check inline policies and attached policies for PassRole permissions
            all_policies = resource.inline_policies.copy()
            
            # Add attached policy documents if available
            for policy_arn in resource.attached_policies:
                policy_resource = self._find_resource_by_arn_or_name(policy_arn, resources)
                if policy_resource and policy_resource.inline_policies:
                    all_policies.extend(policy_resource.inline_policies)
            
            for policy in all_policies:
                pass_role_targets = self._extract_pass_role_targets(policy)
                
                for target_role in pass_role_targets:
                    target_resource = self._find_resource_by_arn_or_name(target_role, resources)
                    if target_resource:
                        relationships.append((
                            resource.terraform_address,
                            target_resource.terraform_address,
                            self.RELATIONSHIP_TYPES['PASS_ROLE']
                        ))
        
        return relationships
    
    def _find_group_membership_relationships(self, resources: List[IAMResource],
                                             resource_map: Dict[str, IAMResource],
                                             name_to_address: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """Find group membership relationships."""
        relationships = []
        
        for resource in resources:
            if resource.resource_type == ResourceType.USER:
                # Check if user has groups specified
                groups = resource.attributes.get('groups', [])
                for group_name in groups:
                    group_address = name_to_address.get(group_name)
                    if group_address:
                        relationships.append((
                            group_address,
                            resource.terraform_address,
                            self.RELATIONSHIP_TYPES['GROUP_MEMBERSHIP']
                        ))
        
        return relationships
    
    def _find_instance_profile_relationships(self, resources: List[IAMResource],
                                             resource_map: Dict[str, IAMResource],
                                             name_to_address: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """Find instance profile relationships."""
        relationships = []
        
        for resource in resources:
            if resource.resource_type == ResourceType.INSTANCE_PROFILE:
                # Find associated roles
                roles = resource.attributes.get('roles', [])
                role_name = resource.attributes.get('role')  # Single role
                
                if role_name:
                    roles.append(role_name)
                
                for role_name in roles:
                    role_address = name_to_address.get(role_name)
                    if role_address:
                        relationships.append((
                            role_address,
                            resource.terraform_address,
                            self.RELATIONSHIP_TYPES['INSTANCE_PROFILE']
                        ))
        
        return relationships
    
    def _find_trust_relationships(self, resources: List[IAMResource],
                                  resource_map: Dict[str, IAMResource]) -> List[Tuple[str, str, str]]:
        """Find trust relationships from assume role policies."""
        relationships = []
        
        for resource in resources:
            if resource.trust_relationships:
                for trusted_principal in resource.trust_relationships:
                    # Try to find the trusted principal as a resource
                    principal_resource = self._find_resource_by_principal(trusted_principal, resources)
                    if principal_resource:
                        relationships.append((
                            principal_resource.terraform_address,
                            resource.terraform_address,
                            self.RELATIONSHIP_TYPES['TRUST_RELATIONSHIP']
                        ))
        
        return relationships
    
    def _extract_principals_from_policy(self, policy: Dict[str, Any]) -> List[str]:
        """Extract principals from an assume role policy."""
        principals = []
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                
                if isinstance(principal, dict):
                    # Extract AWS principals
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        principals.append(aws_principals)
                    elif isinstance(aws_principals, list):
                        principals.extend(aws_principals)
                    
                    # Extract service principals
                    service_principals = principal.get('Service', [])
                    if isinstance(service_principals, str):
                        principals.append(service_principals)
                    elif isinstance(service_principals, list):
                        principals.extend(service_principals)
                
                elif isinstance(principal, str):
                    principals.append(principal)
        
        return principals
    
    def _extract_pass_role_targets(self, policy: Dict[str, Any]) -> List[str]:
        """Extract role ARNs from iam:PassRole actions in a policy."""
        targets = []
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check if PassRole action is present
                has_pass_role = any(
                    action == 'iam:PassRole' or 
                    (action.startswith('iam:') and '*' in action) or
                    action == '*'
                    for action in actions
                )
                
                if has_pass_role:
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    for resource_arn in resources:
                        if isinstance(resource_arn, str) and 'role/' in resource_arn:
                            targets.append(resource_arn)
        
        return targets
    
    def _find_resource_by_principal(self, principal: str, resources: List[IAMResource]) -> Optional[IAMResource]:
        """Find a resource that matches a principal identifier."""
        # Try to match by ARN
        for resource in resources:
            if resource.arn == principal:
                return resource
        
        # Try to match by service principal patterns
        if principal.endswith('.amazonaws.com'):
            # This is a service principal, not a resource
            return None
        
        # Try to match by account/root patterns
        if 'arn:aws:iam::' in principal and ':root' in principal:
            # This is an account root, not a specific resource
            return None
        
        return None
    
    def _find_resource_by_arn_or_name(self, identifier: str, resources: List[IAMResource]) -> Optional[IAMResource]:
        """Find a resource by ARN or name."""
        # Try exact ARN match first
        for resource in resources:
            if resource.arn == identifier:
                return resource
        
        # Try name match
        for resource in resources:
            if resource.display_name == identifier or resource.name == identifier:
                return resource
        
        # Try to extract name from ARN
        if 'arn:aws:iam::' in identifier:
            # Extract resource name from ARN
            arn_parts = identifier.split('/')
            if len(arn_parts) > 1:
                resource_name = arn_parts[-1]
                for resource in resources:
                    if resource.display_name == resource_name or resource.name == resource_name:
                        return resource
        
        return None
    
    def _find_resource_by_name(self, name: str, resources: List[IAMResource]) -> Optional[IAMResource]:
        """Find a resource by name."""
        for resource in resources:
            if resource.display_name == name or resource.name == name:
                return resource
        return None
    
    def _get_visual_attributes(self, resource: IAMResource) -> Dict[str, Any]:
        """Get visual attributes for graph rendering."""
        # Color coding by resource type
        type_colors = {
            ResourceType.USER: '#87CEEB',      # Sky blue
            ResourceType.ROLE: '#98FB98',      # Pale green
            ResourceType.POLICY: '#FFB6C1',    # Light pink
            ResourceType.GROUP: '#DDA0DD',     # Plum
            ResourceType.INSTANCE_PROFILE: '#F0E68C',  # Khaki
            ResourceType.ACCESS_KEY: '#FFA07A', # Light salmon
            ResourceType.ROLE_POLICY: '#FFE4E1',  # Misty rose
            ResourceType.USER_POLICY: '#E0FFFF',  # Light cyan
            ResourceType.GROUP_POLICY: '#F5DEB3'  # Wheat
        }
        
        # Size based on number of relationships/policies
        base_size = 30
        policy_count = len(resource.inline_policies) + len(resource.attached_policies)
        size = base_size + (policy_count * 5)
        
        return {
            'color': type_colors.get(resource.resource_type, '#D3D3D3'),
            'size': min(size, 100),  # Cap at 100
            'shape': 'dot',
            'font': {'size': 12},
            'title': self._create_node_tooltip(resource)
        }
    
    def _get_edge_visual_attributes(self, relationship_type: str) -> Dict[str, Any]:
        """Get visual attributes for edge rendering."""
        # Color and style by relationship type
        edge_styles = {
            'assume_role': {'color': '#FF6B6B', 'width': 3, 'arrows': 'to'},
            'policy_attachment': {'color': '#4ECDC4', 'width': 2, 'arrows': 'to'},
            'inline_policy': {'color': '#45B7D1', 'width': 2, 'arrows': 'to'},
            'pass_role': {'color': '#FFA07A', 'width': 2, 'arrows': 'to', 'dashes': True},
            'group_membership': {'color': '#98D8C8', 'width': 1, 'arrows': 'to'},
            'instance_profile': {'color': '#F7DC6F', 'width': 2, 'arrows': 'to'},
            'trust_relationship': {'color': '#BB8FCE', 'width': 1, 'arrows': 'to', 'dashes': True}
        }
        
        return edge_styles.get(relationship_type, {'color': '#999999', 'width': 1, 'arrows': 'to'})
    
    def _create_node_tooltip(self, resource: IAMResource) -> str:
        """Create tooltip text for a node."""
        tooltip_parts = [
            f"Type: {resource.resource_type.value}",
            f"Name: {resource.display_name}",
            f"Address: {resource.terraform_address}"
        ]
        
        if resource.description:
            tooltip_parts.append(f"Description: {resource.description}")
        
        if resource.tags:
            tag_str = ', '.join([f"{k}={v}" for k, v in resource.tags.items()])
            tooltip_parts.append(f"Tags: {tag_str}")
        
        if resource.inline_policies:
            tooltip_parts.append(f"Inline Policies: {len(resource.inline_policies)}")
        
        if resource.attached_policies:
            tooltip_parts.append(f"Attached Policies: {len(resource.attached_policies)}")
        
        if resource.has_wildcard_permissions():
            tooltip_parts.append("⚠️ Has wildcard permissions")
        
        return '<br>'.join(tooltip_parts)
    
    def _calculate_edge_weight(self, relationship_type: str) -> float:
        """Calculate edge weight based on relationship type."""
        # Higher weights for more critical relationships
        weights = {
            'assume_role': 1.0,
            'policy_attachment': 0.8,
            'inline_policy': 0.8,
            'pass_role': 0.9,
            'group_membership': 0.6,
            'instance_profile': 0.7,
            'trust_relationship': 0.5
        }
        
        return weights.get(relationship_type, 0.5)
    
    def _add_graph_metrics(self, graph: nx.DiGraph):
        """Add graph-level metrics as graph attributes."""
        # Basic metrics
        graph.graph['num_nodes'] = graph.number_of_nodes()
        graph.graph['num_edges'] = graph.number_of_edges()
        graph.graph['density'] = nx.density(graph)
        
        # Connectivity metrics
        if graph.number_of_nodes() > 0:
            graph.graph['is_connected'] = nx.is_weakly_connected(graph)
            graph.graph['num_weakly_connected_components'] = nx.number_weakly_connected_components(graph)
            graph.graph['num_strongly_connected_components'] = nx.number_strongly_connected_components(graph)
        
        # Centrality metrics (for small graphs)
        if graph.number_of_nodes() <= 1000:  # Avoid expensive computation for large graphs
            try:
                centrality = nx.degree_centrality(graph)
                if centrality:
                    max_centrality_node = max(centrality, key=centrality.get)
                    graph.graph['max_centrality_node'] = max_centrality_node
                    graph.graph['max_centrality_value'] = centrality[max_centrality_node]
            except:
                pass  # Skip if computation fails
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the graph building process.
        
        Returns:
            Dictionary containing graph building statistics
        """
        return {
            'nodes_created': self.graph_stats['nodes_created'],
            'edges_created': self.graph_stats['edges_created'],
            'isolated_nodes': self.graph_stats['isolated_nodes'],
            'relationships_by_type': self.graph_stats['relationships_by_type'],
            'connectivity_ratio': (
                (self.graph_stats['nodes_created'] - self.graph_stats['isolated_nodes']) /
                max(1, self.graph_stats['nodes_created'])
            ) * 100
        }
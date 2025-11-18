"""
Main NLP Context Module implementation.

This module implements the NLPContextModule interface and orchestrates
keyword analysis, semantic analysis, and risk score calculation.
"""

import logging
from typing import Dict, List, Tuple, Any
import networkx as nx
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from src.core.interfaces import NLPContextModule
from src.core.data_models import IAMResource, RiskAnalysis
from config.settings import Config
from src.analyzers.risk_keyword_analyzer import RiskKeywordAnalyzer
from src.analyzers.semantic_analyzer import SemanticAnalyzer, TRANSFORMERS_AVAILABLE
from src.analyzers.risk_score_calculator import RiskScoreCalculator


class NLPContextModuleImpl(NLPContextModule):
    """
    Implementation of the NLP Context Module interface.
    
    Orchestrates keyword analysis, semantic analysis, and risk score calculation
    to enhance IAM resources with comprehensive risk assessments.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the NLP context module.
        
        Args:
            config: Configuration object containing NLP settings
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Initialize sub-components
        self.keyword_analyzer = RiskKeywordAnalyzer(config)
        self.risk_calculator = RiskScoreCalculator(config)
        
        # Initialize semantic analyzer if transformers is available
        self.semantic_analyzer = None
        if TRANSFORMERS_AVAILABLE:
            try:
                self.semantic_analyzer = SemanticAnalyzer(config)
                self.logger.info("Semantic analyzer initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize semantic analyzer: {e}")
                self.logger.info("Falling back to keyword-only analysis")
        else:
            self.logger.warning("Transformers library not available. Using keyword-only analysis")
        
        # Cache for analysis results
        self._analysis_cache = {}
        
        # Statistics
        self.module_stats = {
            'resources_analyzed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'semantic_analysis_enabled': self.semantic_analyzer is not None
        }
    
    def analyze_resource_risk(self, resource: IAMResource) -> RiskAnalysis:
        """
        Analyze risk for a single IAM resource using NLP techniques.
        
        Args:
            resource: IAM resource to analyze
            
        Returns:
            RiskAnalysis object containing risk scores and analysis details
        """
        self.logger.debug(f"Analyzing risk for resource: {resource.terraform_address}")
        
        # Check cache first
        cache_key = self._get_cache_key(resource)
        if cache_key in self._analysis_cache:
            self.module_stats['cache_hits'] += 1
            return self._analysis_cache[cache_key]
        
        self.module_stats['cache_misses'] += 1
        
        # Get text content for analysis
        text_content = resource.get_text_content()
        
        # Perform keyword analysis
        keyword_score, matched_keywords = self.analyze_keyword_risk(text_content)
        
        # Perform semantic analysis if available
        semantic_score = 0.0
        semantic_similarities = {}
        
        if self.semantic_analyzer and text_content.strip():
            try:
                semantic_score, semantic_similarities = self.analyze_semantic_risk(text_content)
            except Exception as e:
                self.logger.warning(f"Semantic analysis failed for {resource.terraform_address}: {e}")
        
        # Calculate comprehensive risk score
        risk_analysis = self.risk_calculator.calculate_risk_score(
            resource, keyword_score, matched_keywords, semantic_score, semantic_similarities
        )
        
        # Cache the result
        self._analysis_cache[cache_key] = risk_analysis
        
        # Update statistics
        self.module_stats['resources_analyzed'] += 1
        
        self.logger.debug(
            f"Risk analysis complete for {resource.terraform_address}: "
            f"score={risk_analysis.final_risk_score:.3f}, "
            f"level={risk_analysis.risk_level.value}"
        )
        
        return risk_analysis
    
    def analyze_keyword_risk(self, text: str) -> Tuple[float, List[str]]:
        """
        Analyze risk based on keyword matching.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, matched_keywords)
        """
        return self.keyword_analyzer.analyze_keyword_risk(text)
    
    def analyze_semantic_risk(self, text: str) -> Tuple[float, Dict[str, float]]:
        """
        Analyze risk using semantic similarity with risk concepts.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, similarity_scores_by_concept)
        """
        if self.semantic_analyzer:
            return self.semantic_analyzer.analyze_semantic_risk(text)
        else:
            return 0.0, {}
    
    def enhance_graph(self, graph: nx.DiGraph) -> nx.DiGraph:
        """
        Enhance graph nodes and edges with NLP-derived risk scores.
        
        Args:
            graph: Original graph with IAM resources
            
        Returns:
            Enhanced graph with risk scores added to nodes and edges
        """
        self.logger.info(f"Enhancing graph with {graph.number_of_nodes()} nodes")
        
        # Create a copy of the graph to avoid modifying the original
        enhanced_graph = graph.copy()
        
        # Enhance nodes with risk analysis
        self._enhance_nodes(enhanced_graph)
        
        # Enhance edges with relationship risk scores
        self._enhance_edges(enhanced_graph)
        
        # Add graph-level risk metrics
        self._add_graph_risk_metrics(enhanced_graph)
        
        self.logger.info("Graph enhancement complete")
        
        return enhanced_graph
    
    def batch_analyze_resources(self, resources: List[IAMResource]) -> Dict[str, RiskAnalysis]:
        """
        Perform batch analysis of multiple resources for efficiency.
        
        Args:
            resources: List of IAM resources to analyze
            
        Returns:
            Dictionary mapping resource IDs to RiskAnalysis objects
        """
        self.logger.info(f"Batch analyzing {len(resources)} resources")
        
        results = {}
        
        # Check if we should use parallel processing
        use_parallel = len(resources) > 10 and self.config.max_workers > 1
        
        if use_parallel:
            results = self._batch_analyze_parallel(resources)
        else:
            results = self._batch_analyze_sequential(resources)
        
        self.logger.info(f"Batch analysis complete: {len(results)} resources analyzed")
        
        return results
    
    def _enhance_nodes(self, graph: nx.DiGraph):
        """
        Enhance graph nodes with risk analysis data.
        
        Args:
            graph: Graph to enhance
        """
        self.logger.debug("Enhancing graph nodes with risk analysis")
        
        # Collect all resources for batch processing
        resources = []
        node_to_resource = {}
        
        for node_id in graph.nodes():
            node_data = graph.nodes[node_id]
            
            # Reconstruct IAMResource from node data
            try:
                resource = self._reconstruct_resource_from_node(node_id, node_data)
                resources.append(resource)
                node_to_resource[node_id] = resource
            except Exception as e:
                self.logger.warning(f"Failed to reconstruct resource for node {node_id}: {e}")
                continue
        
        # Perform batch analysis
        if resources:
            risk_analyses = self.batch_analyze_resources(resources)
            
            # Update nodes with risk analysis results
            for node_id, resource in node_to_resource.items():
                resource_id = resource.terraform_address
                
                if resource_id in risk_analyses:
                    risk_analysis = risk_analyses[resource_id]
                    
                    # Add risk analysis attributes to node
                    graph.nodes[node_id].update({
                        'risk_score': risk_analysis.final_risk_score,
                        'risk_level': risk_analysis.risk_level.value,
                        'keyword_risk_score': risk_analysis.keyword_risk_score,
                        'semantic_risk_score': risk_analysis.semantic_risk_score,
                        'matched_keywords': risk_analysis.matched_keywords,
                        'risk_factors': risk_analysis.risk_factors,
                        'risk_analysis': risk_analysis
                    })
                    
                    # Update visual attributes based on risk
                    self._update_node_visual_attributes(graph, node_id, risk_analysis)
    
    def _enhance_edges(self, graph: nx.DiGraph):
        """
        Enhance graph edges with relationship risk scores.
        
        Args:
            graph: Graph to enhance
        """
        self.logger.debug("Enhancing graph edges with relationship risk scores")
        
        for source, target in graph.edges():
            edge_data = graph.edges[source, target]
            relationship_type = edge_data.get('relationship_type', '')
            
            # Calculate edge risk based on relationship type and connected nodes
            edge_risk = self._calculate_edge_risk(graph, source, target, relationship_type)
            
            # Update edge attributes
            graph.edges[source, target].update({
                'risk_score': edge_risk,
                'risk_level': self._get_risk_level_from_score(edge_risk).value
            })
            
            # Update visual attributes
            self._update_edge_visual_attributes(graph, source, target, edge_risk)
    
    def _calculate_edge_risk(self, graph: nx.DiGraph, source: str, target: str, 
                             relationship_type: str) -> float:
        """
        Calculate risk score for a graph edge.
        
        Args:
            graph: Graph containing the edge
            source: Source node ID
            target: Target node ID
            relationship_type: Type of relationship
            
        Returns:
            Edge risk score (0.0 to 1.0)
        """
        # Base risk by relationship type
        relationship_risks = {
            'assume_role': 0.8,
            'policy_attachment': 0.6,
            'inline_policy': 0.7,
            'pass_role': 0.9,
            'group_membership': 0.4,
            'instance_profile': 0.5,
            'trust_relationship': 0.6
        }
        
        base_risk = relationship_risks.get(relationship_type, 0.5)
        
        # Adjust based on connected node risks
        source_risk = graph.nodes[source].get('risk_score', 0.0)
        target_risk = graph.nodes[target].get('risk_score', 0.0)
        
        # Higher risk if connecting high-risk nodes
        node_risk_factor = (source_risk + target_risk) / 2
        
        # Combine base risk with node risk factor
        edge_risk = (base_risk * 0.7) + (node_risk_factor * 0.3)
        
        return min(edge_risk, 1.0)
    
    def _add_graph_risk_metrics(self, graph: nx.DiGraph):
        """
        Add graph-level risk metrics.
        
        Args:
            graph: Graph to enhance
        """
        if graph.number_of_nodes() == 0:
            return
        
        # Calculate aggregate risk metrics
        node_risks = [
            graph.nodes[node].get('risk_score', 0.0) 
            for node in graph.nodes()
        ]
        
        edge_risks = [
            graph.edges[edge].get('risk_score', 0.0)
            for edge in graph.edges()
        ]
        
        # Graph-level metrics
        graph.graph.update({
            'average_node_risk': sum(node_risks) / len(node_risks) if node_risks else 0.0,
            'max_node_risk': max(node_risks) if node_risks else 0.0,
            'high_risk_nodes': len([r for r in node_risks if r >= 0.7]),
            'average_edge_risk': sum(edge_risks) / len(edge_risks) if edge_risks else 0.0,
            'max_edge_risk': max(edge_risks) if edge_risks else 0.0,
            'high_risk_edges': len([r for r in edge_risks if r >= 0.7])
        })
    
    def _batch_analyze_sequential(self, resources: List[IAMResource]) -> Dict[str, RiskAnalysis]:
        """
        Perform sequential batch analysis.
        
        Args:
            resources: List of resources to analyze
            
        Returns:
            Dictionary of resource ID to RiskAnalysis
        """
        results = {}
        
        # Use tqdm for progress bar if available
        try:
            from tqdm import tqdm
            iterator = tqdm(resources, desc="Analyzing resources")
        except ImportError:
            iterator = resources
        
        for resource in iterator:
            try:
                risk_analysis = self.analyze_resource_risk(resource)
                results[resource.terraform_address] = risk_analysis
            except Exception as e:
                self.logger.error(f"Failed to analyze resource {resource.terraform_address}: {e}")
        
        return results
    
    def _batch_analyze_parallel(self, resources: List[IAMResource]) -> Dict[str, RiskAnalysis]:
        """
        Perform parallel batch analysis.
        
        Args:
            resources: List of resources to analyze
            
        Returns:
            Dictionary of resource ID to RiskAnalysis
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_resource = {
                executor.submit(self.analyze_resource_risk, resource): resource
                for resource in resources
            }
            
            # Collect results
            for future in as_completed(future_to_resource):
                resource = future_to_resource[future]
                try:
                    risk_analysis = future.result()
                    results[resource.terraform_address] = risk_analysis
                except Exception as e:
                    self.logger.error(f"Failed to analyze resource {resource.terraform_address}: {e}")
        
        return results
    
    def _reconstruct_resource_from_node(self, node_id: str, node_data: Dict[str, Any]) -> IAMResource:
        """
        Reconstruct an IAMResource from graph node data.
        
        Args:
            node_id: Node identifier
            node_data: Node attributes
            
        Returns:
            Reconstructed IAMResource
        """
        from src.core.data_models import ResourceType
        
        # Extract resource type
        resource_type_str = node_data.get('resource_type', '')
        try:
            resource_type = ResourceType(resource_type_str)
        except ValueError:
            # Fallback for unknown types
            resource_type = ResourceType.USER
        
        # Create IAMResource from node data
        resource = IAMResource(
            resource_type=resource_type,
            name=node_data.get('name', ''),
            terraform_address=node_id,
            attributes=node_data.get('attributes', {}),
            arn=node_data.get('arn'),
            tags=node_data.get('tags', {}),
            comments=node_data.get('comments', []),
            inline_policies=node_data.get('inline_policies', []),
            attached_policies=node_data.get('attached_policies', []),
            assume_role_policy=node_data.get('assume_role_policy'),
            trust_relationships=node_data.get('trust_relationships', []),
            file_path=node_data.get('file_path'),
            line_number=node_data.get('line_number')
        )
        
        return resource
    
    def _update_node_visual_attributes(self, graph: nx.DiGraph, node_id: str, 
                                       risk_analysis: RiskAnalysis):
        """
        Update node visual attributes based on risk analysis.
        
        Args:
            graph: Graph containing the node
            node_id: Node identifier
            risk_analysis: Risk analysis results
        """
        risk_score = risk_analysis.final_risk_score
        
        # Color based on risk level
        risk_colors = {
            'low': self.config.visualization.low_risk_color,
            'medium': self.config.visualization.medium_risk_color,
            'high': self.config.visualization.high_risk_color,
            'critical': self.config.visualization.critical_risk_color
        }
        
        color = risk_colors.get(risk_analysis.risk_level.value, '#D3D3D3')
        
        # Size based on risk score
        min_size, max_size = self.config.visualization.node_size_range
        size = min_size + (risk_score * (max_size - min_size))
        
        # Update node attributes
        graph.nodes[node_id].update({
            'color': color,
            'size': size,
            'border_width': 2 if risk_score >= 0.7 else 1,
            'border_color': '#FF0000' if risk_score >= 0.9 else '#000000'
        })
        
        # Update tooltip with risk information
        existing_title = graph.nodes[node_id].get('title', '')
        risk_info = (
            f"<br><br><b>Risk Analysis:</b><br>"
            f"Risk Score: {risk_score:.3f}<br>"
            f"Risk Level: {risk_analysis.risk_level.value.title()}<br>"
            f"Keywords: {', '.join(risk_analysis.matched_keywords[:3])}<br>"
            f"Factors: {len(risk_analysis.risk_factors)}"
        )
        
        graph.nodes[node_id]['title'] = existing_title + risk_info
    
    def _update_edge_visual_attributes(self, graph: nx.DiGraph, source: str, target: str, 
                                       edge_risk: float):
        """
        Update edge visual attributes based on risk score.
        
        Args:
            graph: Graph containing the edge
            source: Source node ID
            target: Target node ID
            edge_risk: Edge risk score
        """
        # Width based on risk
        min_width, max_width = self.config.visualization.edge_width_range
        width = min_width + (edge_risk * (max_width - min_width))
        
        # Color intensity based on risk
        if edge_risk >= 0.8:
            color = '#FF4444'  # High risk - bright red
        elif edge_risk >= 0.6:
            color = '#FF8844'  # Medium-high risk - orange
        elif edge_risk >= 0.4:
            color = '#FFAA44'  # Medium risk - yellow-orange
        else:
            color = '#888888'  # Low risk - gray
        
        # Update edge attributes
        graph.edges[source, target].update({
            'width': width,
            'color': color,
            'opacity': 0.7 + (edge_risk * 0.3)  # More opaque for higher risk
        })
    
    def _get_risk_level_from_score(self, score: float):
        """Get risk level enum from score."""
        from src.core.data_models import RiskLevel
        
        if score >= 0.9:
            return RiskLevel.CRITICAL
        elif score >= 0.7:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _get_cache_key(self, resource: IAMResource) -> str:
        """
        Generate cache key for a resource.
        
        Args:
            resource: IAM resource
            
        Returns:
            Cache key string
        """
        # Simple cache key based on resource address and content hash
        import hashlib
        
        content = f"{resource.terraform_address}:{resource.get_text_content()}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about NLP analysis.
        
        Returns:
            Dictionary containing analysis statistics
        """
        stats = {
            'module': self.module_stats.copy(),
            'keyword_analysis': self.keyword_analyzer.get_keyword_statistics(),
            'risk_calculation': self.risk_calculator.get_calculation_statistics()
        }
        
        # Add semantic analysis stats if available
        if self.semantic_analyzer:
            stats['semantic_analysis'] = self.semantic_analyzer.get_analysis_statistics()
        
        # Calculate cache hit rate
        total_requests = self.module_stats['cache_hits'] + self.module_stats['cache_misses']
        if total_requests > 0:
            stats['module']['cache_hit_rate'] = (
                self.module_stats['cache_hits'] / total_requests
            ) * 100
        else:
            stats['module']['cache_hit_rate'] = 0.0
        
        return stats
    
    def clear_cache(self):
        """Clear all cached analysis results."""
        self._analysis_cache.clear()
        
        if self.semantic_analyzer:
            self.semantic_analyzer.clear_cache()
        
        self.logger.info("Cleared NLP analysis cache")
    
    def save_cache(self):
        """Save caches to disk."""
        if self.semantic_analyzer:
            self.semantic_analyzer.save_cache()
        
        self.logger.info("Saved NLP analysis caches")
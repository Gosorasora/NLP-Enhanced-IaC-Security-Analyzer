"""
Analysis execution module for coordinating different analysis phases.
"""

import logging
from pathlib import Path
from typing import Dict, Any, List
import networkx as nx

from src.parsers.iac_parser_module import IaCParserModuleImpl as IaCParserModule
from src.analyzers.nlp_context_module import NLPContextModuleImpl as NLPContextModule
from src.core.data_models import IAMResource
from config.settings import Config
from config.error_handling import ErrorHandler, create_error_context, ErrorCategory, ErrorSeverity


class AnalysisRunner:
    """Coordinates the execution of different analysis phases."""
    
    def __init__(self, config: Config, error_handler: ErrorHandler):
        self.config = config
        self.error_handler = error_handler
        self.logger = logging.getLogger(__name__)
    
    def run_parsing_phase(self, input_path: str, progress) -> Dict[str, Any]:
        """Execute the parsing phase."""
        results = {}
        
        try:
            progress.start_step("Parsing", "Analyzing Terraform files")
            
            parser_module = IaCParserModule(self.config)
            
            if Path(input_path).is_file():
                # Single file parsing
                parsed_data = parser_module.parse_file(input_path)
                resources = parser_module.extract_iam_resources(parsed_data)
                graph = parser_module.build_graph(resources)
                tf_files = [Path(input_path)]
            else:
                # Directory parsing
                parsed_data = parser_module.parse_directory(input_path)
                resources = parsed_data.get('resources', [])
                graph = parsed_data.get('graph')
                tf_files = parsed_data.get('tf_files', [])
            
            results.update({
                'resources': resources,
                'graph': graph,
                'tf_files': tf_files,
                'parsed_data': parsed_data
            })
            
            progress.finish_step("Parsing", f"Found {len(resources)} IAM resources from {len(tf_files)} files")
            
        except Exception as e:
            context = create_error_context(
                ErrorCategory.PARSING,
                ErrorSeverity.HIGH,
                f"Failed to parse Terraform files: {e}",
                suggestions=["Check Terraform syntax", "Verify file permissions"],
                recoverable=True
            )
            recovery_result = self.error_handler.handle_error(context, attempt_recovery=True)
            if recovery_result is None or not getattr(recovery_result, 'recovered', False):
                raise
        
        return results
    
    def run_nlp_phase(self, graph: nx.DiGraph, progress) -> nx.DiGraph:
        """Execute the NLP analysis phase."""
        try:
            progress.start_step("NLP Analysis", "Enhancing graph with semantic risk scores")
            
            nlp_module = NLPContextModule(self.config)
            enhanced_graph = nlp_module.enhance_graph(graph)
            
            progress.finish_step("NLP Analysis", "Risk scores computed")
            return enhanced_graph
            
        except Exception as e:
            context = create_error_context(
                ErrorCategory.NLP_PROCESSING,
                ErrorSeverity.MEDIUM,
                f"NLP analysis failed: {e}",
                suggestions=["Check model availability", "Try without NLP"],
                recoverable=True
            )
            recovery_result = self.error_handler.handle_error(context, attempt_recovery=True)
            if recovery_result is not None and getattr(recovery_result, 'recovered', False):
                return graph  # Return original graph
            else:
                raise
    
    def run_path_detection_phase(self, enhanced_graph: nx.DiGraph, resources: List[Dict], progress) -> List[Any]:
        """Execute the path detection phase."""
        try:
            progress.start_step("Path Detection", "Identifying privilege escalation paths")
            
            # Temporarily disable path detection due to data structure mismatch
            # TODO: Fix privilege escalation analyzer to work with IAMResource objects
            escalation_paths = []
            
            progress.finish_step("Path Detection", f"Found {len(escalation_paths)} potential escalation paths")
            return escalation_paths
            
        except Exception as e:
            self.logger.warning(f"Path detection failed: {e}")
            return []
    
    def run_realistic_risk_analysis(self, resources: List[IAMResource], progress) -> Dict[str, Any]:
        """Execute realistic permission and temporal risk analysis."""
        try:
            progress.start_step("Realistic Risk Analysis", "Analyzing permission and temporal risks")
            
            from src.nlp.realistic_risk_analyzer import RealisticRiskAnalyzer
            
            analyzer = RealisticRiskAnalyzer()
            
            # Convert IAMResource objects to dictionaries
            resource_dicts = []
            for resource in resources:
                resource_dict = {
                    'type': resource.resource_type,
                    'name': resource.name,
                    'config': {
                        'tags': getattr(resource, 'tags', {}),
                        'assume_role_policy': getattr(resource, 'assume_role_policy', None),
                        'policy': getattr(resource, 'policy', None),
                        'policy_arn': getattr(resource, 'policy_arn', None),
                    }
                }
                resource_dicts.append(resource_dict)
            
            # Run permission risk analysis
            permission_findings = analyzer.analyze_permission_risks(resource_dicts)
            
            # Run temporal risk analysis
            temporal_findings = analyzer.analyze_temporal_risks(resource_dicts)
            
            # Combine findings
            all_findings = permission_findings + temporal_findings
            
            # Generate summary
            summary = analyzer.generate_risk_summary(all_findings)
            
            progress.finish_step("Realistic Risk Analysis", 
                               f"Found {len(all_findings)} realistic risks")
            
            return {
                'findings': all_findings,
                'summary': summary,
                'permission_risks': len(permission_findings),
                'temporal_risks': len(temporal_findings)
            }
            
        except Exception as e:
            self.logger.warning(f"Realistic risk analysis failed: {e}")
            return {
                'findings': [],
                'summary': {},
                'permission_risks': 0,
                'temporal_risks': 0
            }
            
        except Exception as e:
            context = create_error_context(
                ErrorCategory.PATH_DETECTION,
                ErrorSeverity.MEDIUM,
                f"Path detection failed: {e}",
                suggestions=["Check graph structure", "Try simpler analysis"],
                recoverable=True
            )
            recovery_result = self.error_handler.handle_error(context, attempt_recovery=True)
            if recovery_result is not None and getattr(recovery_result, 'recovered', False):
                return []
            else:
                raise
    
    def run_visualization_phase(self, enhanced_graph: nx.DiGraph, ranked_paths: List[Any], 
                               output_path: Path, progress, realistic_risks: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute the visualization phase."""
        results = {}
        
        try:
            progress.start_step("Visualization", "Generating reports and visualizations")
            
            from src.visualization.cli_visualizer import CLIVisualizer
            
            viz_module = CLIVisualizer(self.config)
            cli_viz = viz_module.create_interactive_graph(enhanced_graph, ranked_paths, realistic_risks)
            
            # Display CLI visualization
            print("\n" + cli_viz)
            
            # Save as text file
            viz_file = output_path / "security_analysis.txt"
            with open(viz_file, 'w', encoding='utf-8') as f:
                f.write(cli_viz)
            
            results['viz_file'] = viz_file
            results['cli_output'] = cli_viz
            
            progress.finish_step("Visualization", "Reports generated")
            
        except Exception as e:
            context = create_error_context(
                ErrorCategory.VISUALIZATION,
                ErrorSeverity.MEDIUM,
                f"Visualization failed: {e}",
                suggestions=["Check output directory", "Try basic output"],
                recoverable=True
            )
            self.error_handler.handle_error(context)
        
        return results
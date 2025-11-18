"""
Output formatting utilities for analysis results.
"""

import json
from typing import Dict, Any
from pathlib import Path


class OutputFormatter:
    """Formats and displays analysis results."""
    
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
    
    def print_summary(self, results: Dict[str, Any], analysis_time: float, 
                     error_summary: Dict[str, Any]) -> None:
        """Print analysis summary with error information."""
        
        if self.quiet:
            return
        
        print(f"\n{'='*60}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*60}")
        
        # Basic statistics
        if 'resources' in results:
            print(f"IAM Resources Found: {len(results['resources'])}")
        
        if 'ranked_paths' in results:
            print(f"Privilege Escalation Paths: {len(results['ranked_paths'])}")
        
        # Output files
        if 'viz_file' in results:
            print(f"\nInteractive Visualization: {results['viz_file']}")
        
        if 'report_file' in results:
            print(f"Analysis Report: {results['report_file']}")
        
        # Error summary
        if error_summary and error_summary.get('total_issues', 0) > 0:
            print(f"\nERRORS AND WARNINGS:")
            print(f"Total Issues: {error_summary['total_issues']}")
        
        print(f"\nTotal Analysis Time: {analysis_time:.1f} seconds")
        print(f"{'='*60}")
    
    def save_json_results(self, results: Dict[str, Any], output_path: Path) -> Path:
        """Save results in JSON format."""
        
        # Prepare JSON-serializable results
        json_results = self._prepare_json_results(results)
        
        json_file = output_path / "analysis_results.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_results, f, indent=2, default=str)
        
        return json_file
    
    def _prepare_json_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare results for JSON serialization."""
        
        json_results = {
            'metadata': {
                'analyzer_version': '1.0.0',
                'analysis_timestamp': str(results.get('timestamp', '')),
                'total_resources': len(results.get('resources', [])),
                'total_paths': len(results.get('ranked_paths', []))
            },
            'summary': {
                'iam_resources_found': len(results.get('resources', [])),
                'privilege_escalation_paths': len(results.get('ranked_paths', [])),
            },
            'resources': [],
            'relationships': [],
            'paths': [],
            'files_analyzed': []
        }
        
        # Add resource information
        if 'resources' in results:
            for resource in results['resources']:
                json_results['resources'].append({
                    'id': getattr(resource, 'terraform_address', str(resource)),
                    'type': str(getattr(resource, 'resource_type', 'unknown')),
                    'name': getattr(resource, 'name', 'unknown'),
                    'display_name': getattr(resource, 'display_name', 'unknown'),
                    'file_path': getattr(resource, 'file_path', 'unknown'),
                    'line_number': getattr(resource, 'line_number', 0),
                })
        
        # Add analyzed files
        if 'tf_files' in results:
            json_results['files_analyzed'] = [str(f) for f in results['tf_files']]
        
        return json_results
    
    def print_mode_specific_info(self, mode: str, results: Dict[str, Any]) -> None:
        """Print mode-specific information."""
        
        if self.quiet:
            return
        
        if mode == "parse-only":
            print("\n📋 Parse-only mode: Only Terraform parsing was performed.")
            print("   Use --mode full for complete security analysis.")
        
        elif mode == "nlp-only":
            print("\n🧠 NLP-only mode: Only semantic analysis was performed.")
            print("   Use --mode full for complete security analysis including path detection.")
        
        elif mode == "paths-only":
            print("\n🎯 Paths-only mode: Only privilege escalation path detection was performed.")
            if 'ranked_paths' in results and results['ranked_paths']:
                print(f"   Found {len(results['ranked_paths'])} potential escalation paths.")
            else:
                print("   No privilege escalation paths detected.")
        
        elif mode == "viz-only":
            print("\n📊 Visualization-only mode: Only report generation was performed.")
            if 'viz_file' in results:
                print(f"   Visualization saved to: {results['viz_file']}")
    
    def print_recommendations(self, results: Dict[str, Any]) -> None:
        """Print security recommendations based on analysis results."""
        
        if self.quiet:
            return
        
        recommendations = []
        
        # Check for high-risk resources
        if 'resources' in results:
            high_risk_count = sum(1 for r in results['resources'] 
                                if getattr(r, 'risk_score', 0) > 0.7)
            if high_risk_count > 0:
                recommendations.append(
                    f"🔴 Review {high_risk_count} high-risk IAM resources immediately"
                )
        
        # Check for privilege escalation paths
        if 'ranked_paths' in results and results['ranked_paths']:
            recommendations.append(
                f"⚠️  Investigate {len(results['ranked_paths'])} potential privilege escalation paths"
            )
        
        if recommendations:
            print("\n💡 SECURITY RECOMMENDATIONS:")
            for rec in recommendations:
                print(f"   {rec}")
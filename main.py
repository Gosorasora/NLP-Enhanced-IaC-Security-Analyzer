#!/usr/bin/env python3
"""
NLP 기반 IaC 보안 분석기

분석 파이프라인을 조율하는 애플리케이션의 메인 진입점입니다.
"""

import sys
import logging
from pathlib import Path

# Core imports
from config.settings import Config
from config.error_handling import ErrorHandler

# Import separated modules
from src.utils.cli_parser import create_argument_parser, validate_arguments
from src.utils.progress_tracker import ProgressTracker
from src.core.analysis_runner import AnalysisRunner
from src.utils.output_formatter import OutputFormatter


def setup_logging(config: Config):
    """로깅 설정을 구성합니다."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if config.verbose:
        logging.basicConfig(
            level=getattr(logging, config.log_level),
            format=log_format,
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('nlp_iac_analyzer.log')
            ]
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format=log_format,
            handlers=[logging.FileHandler('nlp_iac_analyzer.log')]
        )


def apply_cli_overrides(config: Config, args):
    """Apply command line argument overrides to configuration."""
    if args.verbose:
        config.enable_verbose_logging()
    
    if hasattr(args, 'output_format') and args.output_format:
        config.output_format = args.output_format
    
    if hasattr(args, 'risk_threshold') and args.risk_threshold is not None:
        config.path_detection.min_risk_threshold = args.risk_threshold
    
    if hasattr(args, 'nlp_model') and args.nlp_model:
        config.nlp.model_name = args.nlp_model


def run_analysis_mode(mode: str, args, config: Config, progress: ProgressTracker):
    """Run the specified analysis mode using the AnalysisRunner."""
    error_handler = ErrorHandler(logging.getLogger(__name__))
    
    # Create output directory
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Initialize analysis runner
    runner = AnalysisRunner(config, error_handler)
    results = {}
    
    # Run analysis phases based on mode
    if mode in ["full", "parse-only"]:
        parsing_results = runner.run_parsing_phase(args.terraform_dir, progress)
        results.update(parsing_results)
    
    if mode in ["full", "nlp-only"] and not getattr(args, 'disable_nlp', False):
        if 'graph' in results:
            enhanced_graph = runner.run_nlp_phase(results['graph'], progress)
            results['enhanced_graph'] = enhanced_graph
    
    if mode in ["full", "paths-only"]:
        graph = results.get('enhanced_graph', results.get('graph'))
        resources = results.get('resources', [])
        if graph and resources:
            ranked_paths = runner.run_path_detection_phase(graph, resources, progress)
            results['ranked_paths'] = ranked_paths
            
            # Run realistic risk analysis
            realistic_risks = runner.run_realistic_risk_analysis(resources, progress)
            results['realistic_risks'] = realistic_risks
    
    if mode in ["full", "viz-only"]:
        graph = results.get('enhanced_graph', results.get('graph'))
        paths = results.get('ranked_paths', [])
        realistic_risks = results.get('realistic_risks')
        if graph:
            viz_results = runner.run_visualization_phase(graph, paths, output_path, progress, realistic_risks)
            results.update(viz_results)
    
    return results


def main():
    """Main entry point for the NLP-enhanced IaC security analyzer."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Validate arguments
    try:
        validate_arguments(args)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Load configuration
    try:
        config = Config.load_config(args.config)
        apply_cli_overrides(config, args)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)
    
    # Setup logging
    setup_logging(config)
    
    # Initialize progress tracker and output formatter
    progress = ProgressTracker(quiet=getattr(args, 'quiet', False))
    formatter = OutputFormatter(quiet=getattr(args, 'quiet', False))
    
    if not getattr(args, 'quiet', False):
        print("NLP-Enhanced IaC Security Analyzer")
        print(f"Mode: {args.mode}")
        print(f"Input: {args.terraform_dir}")
        print(f"Output: {args.output_dir}")
        print()
    
    try:
        # Run analysis
        results = run_analysis_mode(args.mode, args, config, progress)
        
        # Print summary using output formatter
        analysis_time = progress.get_total_time()
        error_summary = results.get('error_summary', {})
        
        formatter.print_summary(results, analysis_time, error_summary)
        formatter.print_mode_specific_info(args.mode, results)
        formatter.print_recommendations(results)
        
        # Save JSON results if requested
        if getattr(args, 'output_format', 'cli') in ['json', 'both']:
            output_path = Path(args.output_dir)
            json_file = formatter.save_json_results(results, output_path)
            if not getattr(args, 'quiet', False):
                print(f"\nJSON results saved to: {json_file}")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
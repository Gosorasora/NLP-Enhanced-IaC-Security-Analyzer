"""
Command line argument parsing utilities.
"""

import argparse
from pathlib import Path


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the command line argument parser."""
    
    parser = argparse.ArgumentParser(
        description="NLP-Enhanced IaC Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single file
  python3 main.py terraform_samples/iam.tf --mode full
  
  # Analyze directory with parsing only
  python3 main.py terraform_samples --mode parse-only
  
  # Full analysis with custom config
  python3 main.py terraform_samples --mode full --config custom_config.yaml
  
  # Quiet mode with JSON output
  python3 main.py terraform_samples --mode full --quiet --output-format json
        """
    )
    
    # Positional arguments
    parser.add_argument(
        "terraform_dir",
        help="Path to Terraform file or directory to analyze"
    )
    
    # Analysis mode
    parser.add_argument(
        "--mode",
        choices=["full", "parse-only", "nlp-only", "paths-only", "viz-only"],
        default="full",
        help="Analysis mode to run (default: full)"
    )
    
    # Configuration
    parser.add_argument(
        "--config",
        help="Path to custom configuration file"
    )
    
    # Output options
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Output directory for results (default: ./output)"
    )
    
    parser.add_argument(
        "--output-format",
        choices=["cli", "json", "both"],
        default="cli",
        help="Output format (default: cli)"
    )
    
    # Analysis options
    parser.add_argument(
        "--risk-threshold",
        type=float,
        default=0.5,
        help="Risk threshold for flagging resources (0.0-1.0, default: 0.5)"
    )
    
    parser.add_argument(
        "--start-resource",
        help="Starting resource for path analysis"
    )
    
    parser.add_argument(
        "--target-permissions",
        nargs="+",
        help="Target permissions to find paths to"
    )
    
    # NLP options
    parser.add_argument(
        "--nlp-model",
        default="bert-base-uncased",
        help="NLP model to use (default: bert-base-uncased)"
    )
    
    parser.add_argument(
        "--disable-nlp",
        action="store_true",
        help="Disable NLP analysis (faster but less accurate)"
    )
    
    # Behavior options
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--save-intermediate",
        help="Save intermediate results to specified directory"
    )
    
    parser.add_argument(
        "--load-intermediate",
        help="Load intermediate results from specified directory"
    )
    
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    
    # Check if input path exists
    input_path = Path(args.terraform_dir)
    if not input_path.exists():
        raise FileNotFoundError(f"Input path does not exist: {args.terraform_dir}")
    
    # Validate risk threshold
    if not 0.0 <= args.risk_threshold <= 1.0:
        raise ValueError("Risk threshold must be between 0.0 and 1.0")
    
    # Check config file if provided
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file does not exist: {args.config}")
    
    # Validate mode combinations
    if args.mode == "nlp-only" and args.disable_nlp:
        raise ValueError("Cannot use --disable-nlp with --mode nlp-only")
    
    if args.mode == "paths-only" and not args.start_resource:
        print("Warning: paths-only mode works best with --start-resource specified")
    
    # Create output directory if it doesn't exist
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
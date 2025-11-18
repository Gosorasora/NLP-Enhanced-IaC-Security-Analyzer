"""
Extensibility framework for the NLP-enhanced IaC security analyzer.
"""

import os
import importlib
import inspect
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any, Type, Callable, Union
from dataclasses import dataclass, field

from src.core.data_models import IAMResource, RiskAnalysis, Path as AnalysisPath, RankedPath
from src.core.interfaces import NLPContextModule, AttackPathModule, VisualizationModule


class PluginError(Exception):
    """Exception raised for plugin-related errors."""
    pass


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: str
    dependencies: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


class Plugin(ABC):
    """Base class for all plugins."""
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the plugin with configuration.
        
        Args:
            config: Plugin-specific configuration
            
        Returns:
            True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    def cleanup(self):
        """Clean up plugin resources."""
        pass


class RiskAnalysisPlugin(Plugin):
    """Base class for custom risk analysis plugins."""
    
    @abstractmethod
    def analyze_resource(self, resource: IAMResource, context: Dict[str, Any]) -> RiskAnalysis:
        """
        Analyze a resource and return risk assessment.
        
        Args:
            resource: IAM resource to analyze
            context: Additional context for analysis
            
        Returns:
            Risk analysis result
        """
        pass
    
    @abstractmethod
    def get_supported_resource_types(self) -> List[str]:
        """Return list of supported resource types."""
        pass


class CloudProviderPlugin(Plugin):
    """Base class for cloud provider plugins."""
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the cloud provider name (e.g., 'aws', 'azure', 'gcp')."""
        pass
    
    @abstractmethod
    def parse_iac_files(self, directory: str) -> Dict[str, Any]:
        """
        Parse IaC files for this cloud provider.
        
        Args:
            directory: Directory containing IaC files
            
        Returns:
            Parsed IaC data
        """
        pass
    
    @abstractmethod
    def extract_iam_resources(self, parsed_data: Dict[str, Any]) -> List[IAMResource]:
        """
        Extract IAM resources from parsed data.
        
        Args:
            parsed_data: Parsed IaC data
            
        Returns:
            List of IAM resources
        """
        pass
    
    @abstractmethod
    def get_resource_relationships(self, resources: List[IAMResource]) -> List[tuple]:
        """
        Get relationships between resources.
        
        Args:
            resources: List of IAM resources
            
        Returns:
            List of (source, target, relationship_type) tuples
        """
        pass


class VisualizationPlugin(Plugin):
    """Base class for visualization plugins."""
    
    @abstractmethod
    def create_visualization(self, graph: Any, attack_paths: List[RankedPath], config: Dict[str, Any]) -> str:
        """
        Create a visualization of the analysis results.
        
        Args:
            graph: NetworkX graph with analysis results
            attack_paths: List of ranked attack paths
            config: Visualization configuration
            
        Returns:
            Path to generated visualization file or HTML content
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Return list of supported output formats."""
        pass


class ReportingPlugin(Plugin):
    """Base class for reporting plugins."""
    
    @abstractmethod
    def generate_report(self, analysis_results: Dict[str, Any], config: Dict[str, Any]) -> str:
        """
        Generate a report from analysis results.
        
        Args:
            analysis_results: Complete analysis results
            config: Reporting configuration
            
        Returns:
            Path to generated report file or report content
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Return list of supported report formats."""
        pass


class PluginRegistry:
    """Registry for managing plugins."""
    
    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}
        self._plugin_types: Dict[str, List[Plugin]] = {
            'risk_analysis': [],
            'cloud_provider': [],
            'visualization': [],
            'reporting': []
        }
        self._hooks: Dict[str, List[Callable]] = {}
        self._logger = logging.getLogger(__name__)
    
    def register_plugin(self, plugin: Plugin) -> bool:
        """
        Register a plugin.
        
        Args:
            plugin: Plugin instance to register
            
        Returns:
            True if registration successful, False otherwise
        """
        try:
            metadata = plugin.metadata
            
            if metadata.name in self._plugins:
                self._logger.warning(f"Plugin '{metadata.name}' is already registered")
                return False
            
            # Validate plugin type
            if metadata.plugin_type not in self._plugin_types:
                self._logger.error(f"Unknown plugin type: {metadata.plugin_type}")
                return False
            
            # Register plugin
            self._plugins[metadata.name] = plugin
            self._plugin_types[metadata.plugin_type].append(plugin)
            
            self._logger.info(f"Registered plugin '{metadata.name}' (type: {metadata.plugin_type})")
            return True
            
        except Exception as e:
            self._logger.error(f"Failed to register plugin: {e}")
            return False
    
    def unregister_plugin(self, plugin_name: str) -> bool:
        """
        Unregister a plugin.
        
        Args:
            plugin_name: Name of plugin to unregister
            
        Returns:
            True if unregistration successful, False otherwise
        """
        if plugin_name not in self._plugins:
            return False
        
        plugin = self._plugins[plugin_name]
        
        try:
            plugin.cleanup()
            
            # Remove from registry
            del self._plugins[plugin_name]
            
            # Remove from type registry
            plugin_type = plugin.metadata.plugin_type
            if plugin in self._plugin_types[plugin_type]:
                self._plugin_types[plugin_type].remove(plugin)
            
            self._logger.info(f"Unregistered plugin '{plugin_name}'")
            return True
            
        except Exception as e:
            self._logger.error(f"Failed to unregister plugin '{plugin_name}': {e}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """Get a plugin by name."""
        return self._plugins.get(plugin_name)
    
    def get_plugins_by_type(self, plugin_type: str) -> List[Plugin]:
        """Get all plugins of a specific type."""
        return self._plugin_types.get(plugin_type, [])
    
    def list_plugins(self) -> List[PluginMetadata]:
        """List all registered plugins."""
        return [plugin.metadata for plugin in self._plugins.values()]
    
    def register_hook(self, hook_name: str, callback: Callable):
        """
        Register a hook callback.
        
        Args:
            hook_name: Name of the hook
            callback: Callback function to register
        """
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        
        self._hooks[hook_name].append(callback)
        self._logger.debug(f"Registered hook callback for '{hook_name}'")
    
    def execute_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """
        Execute all callbacks for a hook.
        
        Args:
            hook_name: Name of the hook to execute
            *args: Positional arguments to pass to callbacks
            **kwargs: Keyword arguments to pass to callbacks
            
        Returns:
            List of results from all callbacks
        """
        if hook_name not in self._hooks:
            return []
        
        results = []
        for callback in self._hooks[hook_name]:
            try:
                result = callback(*args, **kwargs)
                results.append(result)
            except Exception as e:
                self._logger.error(f"Hook callback failed for '{hook_name}': {e}")
        
        return results


class PluginLoader:
    """Utility class for loading plugins from files and directories."""
    
    def __init__(self, registry: PluginRegistry):
        self.registry = registry
        self._logger = logging.getLogger(__name__)
    
    def load_plugin_from_file(self, plugin_file: str, config: Dict[str, Any] = None) -> bool:
        """
        Load a plugin from a Python file.
        
        Args:
            plugin_file: Path to plugin file
            config: Plugin configuration
            
        Returns:
            True if loading successful, False otherwise
        """
        try:
            plugin_path = Path(plugin_file)
            if not plugin_path.exists():
                self._logger.error(f"Plugin file not found: {plugin_file}")
                return False
            
            # Import the plugin module
            spec = importlib.util.spec_from_file_location("plugin_module", plugin_file)
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            
            # Find plugin classes in the module
            plugin_classes = []
            for name, obj in inspect.getmembers(plugin_module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, Plugin) and 
                    obj != Plugin and
                    not inspect.isabstract(obj)):
                    plugin_classes.append(obj)
            
            if not plugin_classes:
                self._logger.error(f"No plugin classes found in {plugin_file}")
                return False
            
            # Instantiate and register plugins
            success = True
            for plugin_class in plugin_classes:
                try:
                    plugin_instance = plugin_class()
                    
                    # Initialize plugin
                    if plugin_instance.initialize(config or {}):
                        if self.registry.register_plugin(plugin_instance):
                            self._logger.info(f"Loaded plugin '{plugin_instance.metadata.name}' from {plugin_file}")
                        else:
                            success = False
                    else:
                        self._logger.error(f"Failed to initialize plugin from {plugin_file}")
                        success = False
                        
                except Exception as e:
                    self._logger.error(f"Failed to instantiate plugin from {plugin_file}: {e}")
                    success = False
            
            return success
            
        except Exception as e:
            self._logger.error(f"Failed to load plugin from {plugin_file}: {e}")
            return False
    
    def load_plugins_from_directory(self, plugins_dir: str, config: Dict[str, Any] = None) -> int:
        """
        Load all plugins from a directory.
        
        Args:
            plugins_dir: Directory containing plugin files
            config: Plugin configuration
            
        Returns:
            Number of successfully loaded plugins
        """
        plugins_path = Path(plugins_dir)
        if not plugins_path.exists():
            self._logger.warning(f"Plugins directory not found: {plugins_dir}")
            return 0
        
        loaded_count = 0
        for plugin_file in plugins_path.glob("*.py"):
            if plugin_file.name.startswith("__"):
                continue
            
            if self.load_plugin_from_file(str(plugin_file), config):
                loaded_count += 1
        
        self._logger.info(f"Loaded {loaded_count} plugins from {plugins_dir}")
        return loaded_count
    
    def discover_plugins(self, search_paths: List[str] = None) -> int:
        """
        Discover and load plugins from standard locations.
        
        Args:
            search_paths: Additional paths to search for plugins
            
        Returns:
            Number of successfully loaded plugins
        """
        if search_paths is None:
            search_paths = []
        
        # Standard plugin locations
        standard_paths = [
            "plugins",
            "extensions",
            os.path.expanduser("~/.iac_analyzer/plugins"),
            "/usr/local/share/iac_analyzer/plugins"
        ]
        
        all_paths = standard_paths + search_paths
        total_loaded = 0
        
        for path in all_paths:
            if os.path.exists(path):
                total_loaded += self.load_plugins_from_directory(path)
        
        return total_loaded


class ExtensibilityManager:
    """Main manager for the extensibility framework."""
    
    def __init__(self):
        self.registry = PluginRegistry()
        self.loader = PluginLoader(self.registry)
        self._logger = logging.getLogger(__name__)
    
    def initialize(self, config: Dict[str, Any] = None):
        """
        Initialize the extensibility framework.
        
        Args:
            config: Framework configuration
        """
        if config is None:
            config = {}
        
        # Load built-in plugins
        self._load_builtin_plugins(config.get('builtin_plugins', {}))
        
        # Discover and load external plugins
        search_paths = config.get('plugin_search_paths', [])
        self.loader.discover_plugins(search_paths)
        
        # Register standard hooks
        self._register_standard_hooks()
    
    def _load_builtin_plugins(self, config: Dict[str, Any]):
        """Load built-in plugins."""
        # This would load any built-in plugins that come with the system
        pass
    
    def _register_standard_hooks(self):
        """Register standard hooks for extensibility."""
        standard_hooks = [
            'pre_analysis',
            'post_analysis',
            'pre_resource_analysis',
            'post_resource_analysis',
            'pre_path_detection',
            'post_path_detection',
            'pre_visualization',
            'post_visualization',
            'pre_report_generation',
            'post_report_generation'
        ]
        
        for hook_name in standard_hooks:
            if hook_name not in self.registry._hooks:
                self.registry._hooks[hook_name] = []
    
    def get_cloud_provider_plugins(self) -> List[CloudProviderPlugin]:
        """Get all registered cloud provider plugins."""
        return [p for p in self.registry.get_plugins_by_type('cloud_provider') 
                if isinstance(p, CloudProviderPlugin)]
    
    def get_risk_analysis_plugins(self) -> List[RiskAnalysisPlugin]:
        """Get all registered risk analysis plugins."""
        return [p for p in self.registry.get_plugins_by_type('risk_analysis') 
                if isinstance(p, RiskAnalysisPlugin)]
    
    def get_visualization_plugins(self) -> List[VisualizationPlugin]:
        """Get all registered visualization plugins."""
        return [p for p in self.registry.get_plugins_by_type('visualization') 
                if isinstance(p, VisualizationPlugin)]
    
    def get_reporting_plugins(self) -> List[ReportingPlugin]:
        """Get all registered reporting plugins."""
        return [p for p in self.registry.get_plugins_by_type('reporting') 
                if isinstance(p, ReportingPlugin)]
    
    def create_plugin_template(self, plugin_type: str, plugin_name: str, output_dir: str = "."):
        """
        Create a template for a new plugin.
        
        Args:
            plugin_type: Type of plugin to create
            plugin_name: Name of the plugin
            output_dir: Directory to create the plugin template
        """
        templates = {
            'risk_analysis': self._create_risk_analysis_template,
            'cloud_provider': self._create_cloud_provider_template,
            'visualization': self._create_visualization_template,
            'reporting': self._create_reporting_template
        }
        
        if plugin_type not in templates:
            raise PluginError(f"Unknown plugin type: {plugin_type}")
        
        template_content = templates[plugin_type](plugin_name)
        
        output_path = Path(output_dir) / f"{plugin_name.lower().replace(' ', '_')}_plugin.py"
        with open(output_path, 'w') as f:
            f.write(template_content)
        
        self._logger.info(f"Created plugin template at {output_path}")
    
    def _create_risk_analysis_template(self, plugin_name: str) -> str:
        """Create a risk analysis plugin template."""
        return f'''"""
{plugin_name} Risk Analysis Plugin
"""

from typing import Dict, List, Any
from config.extensibility import RiskAnalysisPlugin, PluginMetadata
from src.core.data_models import IAMResource, RiskAnalysis


class {plugin_name.replace(' ', '')}Plugin(RiskAnalysisPlugin):
    """Custom risk analysis plugin for {plugin_name.lower()}."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            description="Custom risk analysis plugin for {plugin_name.lower()}",
            author="Your Name",
            plugin_type="risk_analysis",
            dependencies=[],
            tags=["custom", "risk-analysis"]
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        # Add initialization logic here
        return True
    
    def cleanup(self):
        """Clean up plugin resources."""
        # Add cleanup logic here
        pass
    
    def analyze_resource(self, resource: IAMResource, context: Dict[str, Any]) -> RiskAnalysis:
        """Analyze a resource and return risk assessment."""
        # Implement your custom risk analysis logic here
        
        # Example implementation:
        keyword_matches = []
        keyword_score = 0.0
        semantic_score = 0.0
        
        # Add your analysis logic here
        
        combined_risk_score = (keyword_score + semantic_score) / 2
        
        return RiskAnalysis(
            keyword_matches=keyword_matches,
            keyword_score=keyword_score,
            semantic_score=semantic_score,
            combined_risk_score=combined_risk_score,
            confidence=0.8
        )
    
    def get_supported_resource_types(self) -> List[str]:
        """Return list of supported resource types."""
        return ["aws_iam_user", "aws_iam_role", "aws_iam_policy"]
'''
    
    def _create_cloud_provider_template(self, plugin_name: str) -> str:
        """Create a cloud provider plugin template."""
        return f'''"""
{plugin_name} Cloud Provider Plugin
"""

from typing import Dict, List, Any
from config.extensibility import CloudProviderPlugin, PluginMetadata
from src.core.data_models import IAMResource


class {plugin_name.replace(' ', '')}Plugin(CloudProviderPlugin):
    """Cloud provider plugin for {plugin_name.lower()}."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            description="Cloud provider plugin for {plugin_name.lower()}",
            author="Your Name",
            plugin_type="cloud_provider",
            cloud_providers=["{plugin_name.lower()}"],
            tags=["cloud-provider"]
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        # Add initialization logic here
        return True
    
    def cleanup(self):
        """Clean up plugin resources."""
        # Add cleanup logic here
        pass
    
    def get_provider_name(self) -> str:
        """Return the cloud provider name."""
        return "{plugin_name.lower()}"
    
    def parse_iac_files(self, directory: str) -> Dict[str, Any]:
        """Parse IaC files for this cloud provider."""
        # Implement parsing logic for your cloud provider's IaC format
        # Return parsed data structure
        return {{}}
    
    def extract_iam_resources(self, parsed_data: Dict[str, Any]) -> List[IAMResource]:
        """Extract IAM resources from parsed data."""
        # Implement resource extraction logic
        resources = []
        
        # Add your extraction logic here
        
        return resources
    
    def get_resource_relationships(self, resources: List[IAMResource]) -> List[tuple]:
        """Get relationships between resources."""
        # Implement relationship detection logic
        relationships = []
        
        # Add your relationship detection logic here
        
        return relationships
'''
    
    def _create_visualization_template(self, plugin_name: str) -> str:
        """Create a visualization plugin template."""
        return f'''"""
{plugin_name} Visualization Plugin
"""

from typing import Dict, List, Any
from config.extensibility import VisualizationPlugin, PluginMetadata
from src.core.data_models import RankedPath


class {plugin_name.replace(' ', '')}Plugin(VisualizationPlugin):
    """Visualization plugin for {plugin_name.lower()}."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            description="Visualization plugin for {plugin_name.lower()}",
            author="Your Name",
            plugin_type="visualization",
            tags=["visualization"]
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        # Add initialization logic here
        return True
    
    def cleanup(self):
        """Clean up plugin resources."""
        # Add cleanup logic here
        pass
    
    def create_visualization(self, graph: Any, attack_paths: List[RankedPath], config: Dict[str, Any]) -> str:
        """Create a visualization of the analysis results."""
        # Implement your custom visualization logic here
        
        # Example: Generate a simple HTML visualization
        html_content = f"""
        <html>
        <head><title>{plugin_name} Visualization</title></head>
        <body>
            <h1>Security Analysis Results</h1>
            <p>Total nodes: {{len(graph.nodes())}}</p>
            <p>Total edges: {{len(graph.edges())}}</p>
            <p>Attack paths found: {{len(attack_paths)}}</p>
        </body>
        </html>
        """
        
        return html_content
    
    def get_supported_formats(self) -> List[str]:
        """Return list of supported output formats."""
        return ["html", "png", "svg"]
'''
    
    def _create_reporting_template(self, plugin_name: str) -> str:
        """Create a reporting plugin template."""
        return f'''"""
{plugin_name} Reporting Plugin
"""

from typing import Dict, List, Any
from config.extensibility import ReportingPlugin, PluginMetadata


class {plugin_name.replace(' ', '')}Plugin(ReportingPlugin):
    """Reporting plugin for {plugin_name.lower()}."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            description="Reporting plugin for {plugin_name.lower()}",
            author="Your Name",
            plugin_type="reporting",
            tags=["reporting"]
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        # Add initialization logic here
        return True
    
    def cleanup(self):
        """Clean up plugin resources."""
        # Add cleanup logic here
        pass
    
    def generate_report(self, analysis_results: Dict[str, Any], config: Dict[str, Any]) -> str:
        """Generate a report from analysis results."""
        # Implement your custom reporting logic here
        
        # Example: Generate a simple text report
        report_content = f"""
{plugin_name} Security Analysis Report
{'=' * 50}

Analysis Summary:
- Total resources analyzed: {{analysis_results.get('total_resources', 0)}}
- High-risk resources: {{len(analysis_results.get('high_risk_resources', []))}}
- Attack paths found: {{len(analysis_results.get('attack_paths', []))}}

Generated by {plugin_name} Plugin
        """
        
        return report_content
    
    def get_supported_formats(self) -> List[str]:
        """Return list of supported report formats."""
        return ["txt", "html", "pdf"]
'''


# Global extensibility manager instance
extensibility_manager = ExtensibilityManager()
"""
CLI-based visualization module for IAM security analysis.
"""

from typing import List, Dict, Any
import networkx as nx


class CLIVisualizer:
    """CLI-based ASCII visualization for IAM security analysis."""
    
    def __init__(self, config=None):
        self.config = config
    
    def create_interactive_graph(self, graph: nx.DiGraph, paths: List[Any], realistic_risks: Dict[str, Any] = None) -> str:
        """Create a CLI-based ASCII visualization of the IAM graph."""
        
        # Extract nodes and edges for CLI visualization
        users = []
        roles = []
        policies = []
        attachments = []
        
        # Categorize nodes
        for node_id, node_data in graph.nodes(data=True):
            resource_type = str(node_data.get('resource_type', 'unknown'))
            display_name = node_data.get('display_name', node_id.split('.')[-1])
            
            # Handle display_name being a list
            if isinstance(display_name, list):
                display_name = display_name[0] if display_name else node_id.split('.')[-1]
            display_name = str(display_name)
            
            risk_level = 'HIGH' if node_data.get('has_wildcard_permissions', False) else 'MED'
            
            if 'user' in resource_type.lower():
                users.append((display_name, risk_level, node_id))
            elif 'role' in resource_type.lower():
                roles.append((display_name, risk_level, node_id))
            elif 'policy' in resource_type.lower() and 'attachment' not in resource_type.lower():
                policies.append((display_name, risk_level, node_id))
            else:
                attachments.append((display_name, risk_level, node_id))
        
        # Extract relationships safely
        relationships = []
        for source, target, edge_data in graph.edges(data=True):
            rel_type = edge_data.get('relationship_type', 'RELATED')
            relationships.append((source, target, rel_type))
        
        return self._generate_cli_output(users, roles, policies, attachments, relationships, paths, realistic_risks)
    
    def _generate_cli_output(self, users, roles, policies, attachments, relationships, paths, realistic_risks=None):
        """Generate the CLI output string."""
        cli_output = []
        cli_output.append("=" * 80)
        cli_output.append("🔍 IAM SECURITY ANALYSIS - NETWORK VISUALIZATION")
        cli_output.append("=" * 80)
        cli_output.append("")
        
        # Statistics
        cli_output.append("📊 SUMMARY STATISTICS")
        cli_output.append("-" * 40)
        cli_output.append(f"👥 IAM Users:      {len(users)}")
        cli_output.append(f"👥 IAM Roles:      {len(roles)}")
        cli_output.append(f"📋 IAM Policies:   {len(policies)}")
        cli_output.append(f"🔗 Attachments:    {len(attachments)}")
        cli_output.append(f"🕸️  Relationships: {len(relationships)}")
        cli_output.append(f"⚠️  Attack Paths:   {len(paths)}")
        cli_output.append("")
        
        # Resource breakdown by risk
        high_risk_count = sum(1 for items in [users, roles, policies, attachments] 
                             for _, risk, _ in items if risk == 'HIGH')
        cli_output.append("🚨 RISK BREAKDOWN")
        cli_output.append("-" * 40)
        cli_output.append(f"🔴 High Risk:      {high_risk_count}")
        cli_output.append(f"🟡 Medium Risk:    {len(users) + len(roles) + len(policies) + len(attachments) - high_risk_count}")
        cli_output.append("")
        
        # Add resource sections
        self._add_resource_sections(cli_output, users, roles, policies)
        
        # Add relationships section
        self._add_relationships_section(cli_output, relationships)
        
        # Add structural analysis
        self._add_structural_analysis(cli_output, relationships)
        
        # Add key findings
        self._add_key_findings(cli_output, users, roles, policies, relationships)
        
        # Add realistic risk analysis results
        if realistic_risks:
            self._add_realistic_risks(cli_output, realistic_risks)
        
        # Add privilege escalation paths
        self._add_escalation_paths(cli_output, paths)
        
        cli_output.append("")
        cli_output.append("=" * 80)
        
        return "\n".join(cli_output)
    
    def _add_resource_sections(self, cli_output, users, roles, policies):
        """Add resource sections to CLI output."""
        # Users section
        if users:
            cli_output.append("👥 IAM USERS")
            cli_output.append("-" * 40)
            for name, risk, node_id in sorted(users):
                risk_icon = "🔴" if risk == "HIGH" else "🟡"
                cli_output.append(f"  {risk_icon} {name}")
            cli_output.append("")
        
        # Roles section
        if roles:
            cli_output.append("🎭 IAM ROLES")
            cli_output.append("-" * 40)
            for name, risk, node_id in sorted(roles):
                risk_icon = "🔴" if risk == "HIGH" else "🟡"
                cli_output.append(f"  {risk_icon} {name}")
            cli_output.append("")
        
        # Policies section
        if policies:
            cli_output.append("📋 IAM POLICIES")
            cli_output.append("-" * 40)
            for name, risk, node_id in sorted(policies):
                risk_icon = "🔴" if risk == "HIGH" else "🟡"
                cli_output.append(f"  {risk_icon} {name}")
            cli_output.append("")
    
    def _add_relationships_section(self, cli_output, relationships):
        """Add relationships section to CLI output."""
        if relationships:
            cli_output.append("🕸️  RESOURCE RELATIONSHIPS")
            cli_output.append("-" * 40)
            
            # Group relationships by type
            rel_groups = {}
            for source, target, rel_type in relationships:
                if rel_type not in rel_groups:
                    rel_groups[rel_type] = []
                rel_groups[rel_type].append((source, target))
            
            for rel_type, rels in rel_groups.items():
                cli_output.append(f"  📌 {rel_type}:")
                for source, target in rels[:5]:  # Show max 5 per type
                    source_name = source.split('.')[-1]
                    target_name = target.split('.')[-1]
                    cli_output.append(f"     {source_name} ──→ {target_name}")
                if len(rels) > 5:
                    cli_output.append(f"     ... and {len(rels) - 5} more")
                cli_output.append("")
    
    def _add_structural_analysis(self, cli_output, relationships):
        """Add structural privilege escalation analysis."""
        cli_output.append("🚨 STRUCTURAL PRIVILEGE ESCALATION RISKS")
        cli_output.append("-" * 40)
        
        # Analyze direct user policy attachments
        direct_attachments = {}
        
        for source, target, rel_type in relationships:
            if rel_type == "ATTACHED_TO":
                source_name = source.split('.')[-1]
                target_name = target.split('.')[-1]
                
                if 'user' in source.lower():
                    if source_name not in direct_attachments:
                        direct_attachments[source_name] = []
                    direct_attachments[source_name].append(target_name)
        
        if direct_attachments:
            cli_output.append(f"  ⚠️  {len(direct_attachments)} users have direct policy attachments:")
            for user, policies in list(direct_attachments.items())[:5]:  # Show top 5
                policy_str = ", ".join(policies[:2])  # Show first 2 policies
                if len(policies) > 2:
                    policy_str += f" (+{len(policies)-2} more)"
                cli_output.append(f"     • {user} → {policy_str}")
            if len(direct_attachments) > 5:
                cli_output.append(f"     ... and {len(direct_attachments)-5} more users")
        else:
            cli_output.append("  ✅ No direct user policy attachments found")
        
        cli_output.append("")
    
    def _add_key_findings(self, cli_output, users, roles, policies, relationships):
        """Add key findings section."""
        cli_output.append("🔍 KEY FINDINGS")
        cli_output.append("-" * 40)
        
        findings = []
        
        # Check for admin users
        admin_users = [name for name, _, _ in users if any(keyword in name.lower() 
                      for keyword in ['admin', 'root', 'super', 'god', 'master'])]
        if admin_users:
            findings.append(f"⚠️  Found {len(admin_users)} users with admin-like names")
        
        # Check for temp/test users
        temp_users = [name for name, _, _ in users if any(keyword in name.lower() 
                     for keyword in ['temp', 'test', 'debug', 'dev'])]
        if temp_users:
            findings.append(f"⚠️  Found {len(temp_users)} temporary/test users")
        
        # Check for external access
        external_users = [name for name, _, _ in users if any(keyword in name.lower() 
                         for keyword in ['vendor', 'contractor', 'external', 'third'])]
        if external_users:
            findings.append(f"⚠️  Found {len(external_users)} external/vendor users")
        
        # Check for bypass/backdoor roles
        bypass_roles = [name for name, _, _ in roles if any(keyword in name.lower() 
                       for keyword in ['bypass', 'backdoor', 'emergency', 'break'])]
        if bypass_roles:
            findings.append(f"🚨 Found {len(bypass_roles)} bypass/backdoor roles")
        
        # Check for wildcard policies
        wildcard_policies = [name for name, _, _ in policies if 'wildcard' in name.lower()]
        if wildcard_policies:
            findings.append(f"🚨 Found {len(wildcard_policies)} wildcard policies")
        
        # Check for direct user policy attachments (structural privilege escalation risk)
        direct_user_attachments = []
        external_user_attachments = []
        temp_user_attachments = []
        
        for source, target, rel_type in relationships:
            if rel_type == "ATTACHED_TO":
                source_name = source.split('.')[-1]
                target_name = target.split('.')[-1]
                
                # Check if it's a user with direct policy attachment
                if 'user' in source.lower() and ('policy_attachment' in target.lower() or 'policy' in target.lower()):
                    direct_user_attachments.append(source_name)
                    
                    # Check if it's external/vendor user
                    if any(keyword in source_name.lower() for keyword in ['vendor', 'contractor', 'external', 'third']):
                        external_user_attachments.append(source_name)
                    
                    # Check if it's temporary/test user  
                    if any(keyword in source_name.lower() for keyword in ['temp', 'test', 'debug', 'dev']):
                        temp_user_attachments.append(source_name)
        
        if direct_user_attachments:
            findings.append(f"🚨 Found {len(set(direct_user_attachments))} users with direct policy attachments (privilege escalation risk)")
        
        if external_user_attachments:
            findings.append(f"⚠️  Found {len(set(external_user_attachments))} external users with direct access (external breach risk)")
        
        if temp_user_attachments:
            findings.append(f"⚠️  Found {len(set(temp_user_attachments))} temporary users with direct policies (abandoned access risk)")
        
        # Check for high-privilege direct attachments
        admin_attachments = []
        for source, target, rel_type in relationships:
            if rel_type == "ATTACHED_TO":
                source_name = source.split('.')[-1]
                target_name = target.split('.')[-1]
                
                if ('user' in source.lower() and 
                    any(keyword in target_name.lower() for keyword in ['admin', 'full', 'root', 'super'])):
                    admin_attachments.append(f"{source_name} → {target_name}")
        
        if admin_attachments:
            findings.append(f"🔴 Found {len(admin_attachments)} users with direct admin-level access")
        
        if not findings:
            findings.append("✅ No obvious security issues detected")
        
        for finding in findings:
            cli_output.append(f"  {finding}")
  
  
    def _add_escalation_paths(self, cli_output, paths):
        """Add privilege escalation paths section."""
        if not paths:
            return
        
        cli_output.append("")
        cli_output.append("🚨 PRIVILEGE ESCALATION PATHS")
        cli_output.append("-" * 40)
        
        # Group paths by type
        paths_by_type = {}
        for path in paths:
            escalation_type = path.escalation_type
            if escalation_type not in paths_by_type:
                paths_by_type[escalation_type] = []
            paths_by_type[escalation_type].append(path)
        
        # Display paths by type
        for escalation_type, type_paths in sorted(paths_by_type.items()):
            cli_output.append(f"\n  📍 {escalation_type.upper().replace('_', ' ')} ({len(type_paths)} paths):")
            
            # Show top 3 paths of each type
            for path in sorted(type_paths, key=lambda x: x.risk_score, reverse=True)[:3]:
                risk_icon = "🔴" if path.risk_score >= 80 else "🟡" if path.risk_score >= 50 else "🟢"
                cli_output.append(f"     {risk_icon} Risk: {path.risk_score}/100")
                cli_output.append(f"        Path: {' → '.join(path.path)}")
                cli_output.append(f"        {path.description}")
                if path.evidence:
                    cli_output.append(f"        Evidence: {path.evidence[0]}")
                cli_output.append("")

    
    def _add_realistic_risks(self, cli_output, realistic_risks):
        """Add realistic permission and temporal risk analysis results."""
        if not realistic_risks or not realistic_risks.get('findings'):
            return
        
        cli_output.append("")
        cli_output.append("🎯 REALISTIC RISK ANALYSIS")
        cli_output.append("-" * 40)
        
        summary = realistic_risks.get('summary', {})
        findings = realistic_risks.get('findings', [])
        
        # Summary statistics
        cli_output.append(f"📊 Total Findings: {summary.get('total_findings', 0)}")
        cli_output.append(f"   🔴 High Risk: {summary.get('high_risk', 0)}")
        cli_output.append(f"   🟡 Medium Risk: {summary.get('medium_risk', 0)}")
        cli_output.append(f"   🟢 Low Risk: {summary.get('low_risk', 0)}")
        cli_output.append("")
        
        # Risk types breakdown
        risk_types = summary.get('risk_types', {})
        if risk_types:
            cli_output.append("📋 Risk Types:")
            for risk_type, count in sorted(risk_types.items(), key=lambda x: x[1], reverse=True):
                risk_type_display = risk_type.replace('_', ' ').title()
                cli_output.append(f"   • {risk_type_display}: {count}")
            cli_output.append("")
        
        # Top risks
        top_risks = summary.get('top_risks', [])[:5]
        if top_risks:
            cli_output.append("🚨 Top 5 Critical Risks:")
            for i, finding in enumerate(top_risks, 1):
                severity_icon = "🔴" if finding.severity == 'HIGH' else "🟡" if finding.severity == 'MEDIUM' else "🟢"
                cli_output.append(f"\n   {i}. {severity_icon} {finding.resource_name}")
                cli_output.append(f"      Type: {finding.risk_type.replace('_', ' ').title()}")
                cli_output.append(f"      Score: {finding.score}/100")
                cli_output.append(f"      {finding.description}")
                if finding.evidence:
                    cli_output.append(f"      Evidence:")
                    for evidence in finding.evidence[:2]:  # Show first 2 evidence items
                        cli_output.append(f"        - {evidence}")

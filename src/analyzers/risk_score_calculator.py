"""
Risk score calculation engine for IAM resources.

This module combines keyword-based and semantic analysis results to compute
final risk scores with configurable weighting algorithms.
"""

import logging
import re
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

from src.core.data_models import IAMResource, RiskAnalysis, RiskLevel
from config.settings import Config


class RiskFactor(Enum):
    """Enumeration of different risk factors."""
    WILDCARD_PERMISSIONS = "wildcard_permissions"
    ADMIN_ACCESS = "admin_access"
    TEMPORARY_ACCESS = "temporary_access"
    MISSING_DESCRIPTION = "missing_description"
    SUSPICIOUS_NAMING = "suspicious_naming"
    INLINE_POLICIES = "inline_policies"
    MULTIPLE_POLICIES = "multiple_policies"
    CROSS_ACCOUNT_TRUST = "cross_account_trust"
    SERVICE_TRUST = "service_trust"
    BROAD_RESOURCE_ACCESS = "broad_resource_access"


@dataclass
class RiskFactorAnalysis:
    """Analysis result for a specific risk factor."""
    factor: RiskFactor
    present: bool
    severity: float  # 0.0 to 1.0
    description: str
    evidence: List[str]


class RiskScoreCalculator:
    """
    Calculates comprehensive risk scores for IAM resources.
    
    Combines keyword analysis, semantic analysis, and structural analysis
    to produce final risk scores with detailed explanations.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the risk score calculator.
        
        Args:
            config: Configuration object containing calculation settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Risk factor weights
        self.risk_factor_weights = {
            RiskFactor.WILDCARD_PERMISSIONS: 0.95,
            RiskFactor.ADMIN_ACCESS: 0.90,
            RiskFactor.TEMPORARY_ACCESS: 0.75,
            RiskFactor.MISSING_DESCRIPTION: 0.30,
            RiskFactor.SUSPICIOUS_NAMING: 0.60,
            RiskFactor.INLINE_POLICIES: 0.50,
            RiskFactor.MULTIPLE_POLICIES: 0.40,
            RiskFactor.CROSS_ACCOUNT_TRUST: 0.85,
            RiskFactor.SERVICE_TRUST: 0.20,
            RiskFactor.BROAD_RESOURCE_ACCESS: 0.80
        }
        
        # Statistics tracking
        self.calculation_stats = {
            'resources_analyzed': 0,
            'high_risk_resources': 0,
            'risk_factors_detected': {},
            'average_risk_score': 0.0
        }
    
    def calculate_risk_score(self, resource: IAMResource, 
                             keyword_score: float, keyword_matches: List[str],
                             semantic_score: float, semantic_similarities: Dict[str, float]) -> RiskAnalysis:
        """
        Calculate comprehensive risk score for an IAM resource.
        
        Args:
            resource: IAM resource to analyze
            keyword_score: Risk score from keyword analysis
            keyword_matches: List of matched risk keywords
            semantic_score: Risk score from semantic analysis
            semantic_similarities: Dictionary of concept similarities
            
        Returns:
            RiskAnalysis object with comprehensive risk assessment
        """
        self.logger.debug(f"Calculating risk score for resource: {resource.terraform_address}")
        
        # Analyze structural risk factors
        risk_factors = self._analyze_risk_factors(resource)
        
        # Calculate structural risk score
        structural_score = self._calculate_structural_risk_score(risk_factors)
        
        # Combine all risk scores
        final_score = self._combine_risk_scores(
            keyword_score, semantic_score, structural_score
        )
        
        # Extract risk factors for reporting
        risk_factor_descriptions = [
            f"{factor.description} (severity: {factor.severity:.2f})"
            for factor in risk_factors if factor.present
        ]
        
        # Create risk analysis result
        risk_analysis = RiskAnalysis(
            keyword_risk_score=keyword_score,
            semantic_risk_score=semantic_score,
            final_risk_score=final_score,
            matched_keywords=keyword_matches,
            semantic_similarities=semantic_similarities,
            risk_factors=risk_factor_descriptions
        )
        
        # Add metadata
        risk_analysis.model_version = self.config.nlp.model_name
        
        # Update statistics
        self._update_statistics(risk_analysis, risk_factors)
        
        self.logger.debug(f"Final risk score: {final_score:.3f} ({risk_analysis.risk_level.value})")
        
        return risk_analysis
    
    def analyze_comment_risk(self, comments: List[str]) -> Tuple[float, List[str]]:
        """
        Analyze risk indicators in resource comments.
        
        Args:
            comments: List of comment strings
            
        Returns:
            Tuple of (comment_risk_score, risk_indicators)
        """
        if not comments:
            return 0.0, []
        
        combined_text = ' '.join(comments).lower()
        risk_indicators = []
        risk_score = 0.0
        
        # Comment-specific risk patterns
        comment_risk_patterns = {
            r'\b(todo|fixme|hack|workaround)\b': ('Temporary implementation', 0.6),
            r'\b(disable|bypass|skip)\s+(security|validation|check)\b': ('Security bypass', 0.9),
            r'\b(emergency|urgent|hotfix)\b': ('Emergency access', 0.7),
            r'\b(test|testing|debug)\s+(only|purpose)\b': ('Test/debug purpose', 0.5),
            r'\b(remove|delete)\s+(later|soon|after)\b': ('Temporary resource', 0.6),
            r'\b(admin|root|full)\s+(access|permission)\b': ('Administrative access', 0.8),
            r'\b(temporary|temp)\b': ('Temporary access', 0.7)
        }
        
        for pattern, (description, weight) in comment_risk_patterns.items():
            if re.search(pattern, combined_text):
                risk_indicators.append(description)
                risk_score = max(risk_score, weight)
        
        return risk_score, risk_indicators
    
    def _analyze_risk_factors(self, resource: IAMResource) -> List[RiskFactorAnalysis]:
        """
        Analyze various risk factors for a resource.
        
        Args:
            resource: IAM resource to analyze
            
        Returns:
            List of RiskFactorAnalysis objects
        """
        risk_factors = []
        
        # Wildcard permissions
        risk_factors.append(self._check_wildcard_permissions(resource))
        
        # Admin access patterns
        risk_factors.append(self._check_admin_access(resource))
        
        # Temporary access patterns
        risk_factors.append(self._check_temporary_access(resource))
        
        # Missing description
        risk_factors.append(self._check_missing_description(resource))
        
        # Suspicious naming
        risk_factors.append(self._check_suspicious_naming(resource))
        
        # Inline policies
        risk_factors.append(self._check_inline_policies(resource))
        
        # Multiple policies
        risk_factors.append(self._check_multiple_policies(resource))
        
        # Cross-account trust
        risk_factors.append(self._check_cross_account_trust(resource))
        
        # Service trust
        risk_factors.append(self._check_service_trust(resource))
        
        # Broad resource access
        risk_factors.append(self._check_broad_resource_access(resource))
        
        return risk_factors
    
    def _check_wildcard_permissions(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for wildcard permissions in policies."""
        evidence = []
        severity = 0.0
        
        # Check inline policies
        for policy in resource.inline_policies:
            if self._policy_has_wildcards(policy):
                evidence.append(f"Wildcard permissions in inline policy")
                severity = max(severity, 0.95)
        
        # Check assume role policy
        if resource.assume_role_policy and self._policy_has_wildcards(resource.assume_role_policy):
            evidence.append("Wildcard permissions in assume role policy")
            severity = max(severity, 0.90)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.WILDCARD_PERMISSIONS,
            present=len(evidence) > 0,
            severity=severity,
            description="Resource has wildcard (*) permissions",
            evidence=evidence
        )
    
    def _check_admin_access(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for administrative access patterns."""
        evidence = []
        severity = 0.0
        
        # Check resource name and description
        text_content = resource.get_text_content().lower()
        admin_patterns = ['admin', 'administrator', 'root', 'superuser']
        
        for pattern in admin_patterns:
            if pattern in text_content:
                evidence.append(f"Administrative keyword '{pattern}' in resource text")
                severity = max(severity, 0.8)
        
        # Check for admin-like policies
        for policy in resource.inline_policies:
            if self._policy_has_admin_actions(policy):
                evidence.append("Policy contains administrative actions")
                severity = max(severity, 0.9)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.ADMIN_ACCESS,
            present=len(evidence) > 0,
            severity=severity,
            description="Resource has administrative access patterns",
            evidence=evidence
        )
    
    def _check_temporary_access(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for temporary access patterns."""
        evidence = []
        severity = 0.0
        
        text_content = resource.get_text_content().lower()
        temp_patterns = ['temp', 'temporary', 'tmp', 'test', 'debug', 'emergency']
        
        for pattern in temp_patterns:
            if pattern in text_content:
                evidence.append(f"Temporary keyword '{pattern}' in resource text")
                severity = max(severity, 0.7)
        
        # Check comments for temporary indicators
        comment_risk, comment_indicators = self.analyze_comment_risk(resource.comments)
        if comment_risk > 0:
            evidence.extend(comment_indicators)
            severity = max(severity, comment_risk)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.TEMPORARY_ACCESS,
            present=len(evidence) > 0,
            severity=severity,
            description="Resource appears to be for temporary access",
            evidence=evidence
        )
    
    def _check_missing_description(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for missing resource description."""
        has_description = bool(resource.description or resource.comments)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.MISSING_DESCRIPTION,
            present=not has_description,
            severity=0.3 if not has_description else 0.0,
            description="Resource lacks description or documentation",
            evidence=["No description or comments found"] if not has_description else []
        )
    
    def _check_suspicious_naming(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for suspicious naming patterns."""
        evidence = []
        severity = 0.0
        
        name = resource.display_name.lower()
        
        # Suspicious patterns
        suspicious_patterns = {
            r'\b(backdoor|bypass|hack)\b': 0.95,
            r'\b(test|debug|temp)\d*\b': 0.6,
            r'^(admin|root|super)': 0.8,
            r'\b(emergency|urgent|hotfix)\b': 0.7,
            r'^[a-z]{1,3}\d+$': 0.4,  # Very short names with numbers
        }
        
        for pattern, weight in suspicious_patterns.items():
            if re.search(pattern, name):
                evidence.append(f"Suspicious naming pattern: {pattern}")
                severity = max(severity, weight)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.SUSPICIOUS_NAMING,
            present=len(evidence) > 0,
            severity=severity,
            description="Resource has suspicious naming patterns",
            evidence=evidence
        )
    
    def _check_inline_policies(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for inline policies (generally less secure than managed policies)."""
        has_inline = len(resource.inline_policies) > 0
        
        evidence = []
        if has_inline:
            evidence.append(f"Resource has {len(resource.inline_policies)} inline policies")
        
        return RiskFactorAnalysis(
            factor=RiskFactor.INLINE_POLICIES,
            present=has_inline,
            severity=0.5 if has_inline else 0.0,
            description="Resource uses inline policies instead of managed policies",
            evidence=evidence
        )
    
    def _check_multiple_policies(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for excessive number of policies."""
        total_policies = len(resource.inline_policies) + len(resource.attached_policies)
        
        evidence = []
        severity = 0.0
        
        if total_policies > 5:
            evidence.append(f"Resource has {total_policies} policies (high complexity)")
            severity = min(0.4 + (total_policies - 5) * 0.1, 0.8)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.MULTIPLE_POLICIES,
            present=total_policies > 5,
            severity=severity,
            description="Resource has excessive number of policies",
            evidence=evidence
        )
    
    def _check_cross_account_trust(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for cross-account trust relationships."""
        evidence = []
        severity = 0.0
        
        for principal in resource.trust_relationships:
            if 'arn:aws:iam::' in principal and ':root' in principal:
                # Extract account ID
                account_match = re.search(r'arn:aws:iam::(\d+):root', principal)
                if account_match:
                    account_id = account_match.group(1)
                    evidence.append(f"Cross-account trust with account {account_id}")
                    severity = max(severity, 0.8)
            elif principal == '*':
                evidence.append("Wildcard principal in trust relationship")
                severity = max(severity, 0.95)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.CROSS_ACCOUNT_TRUST,
            present=len(evidence) > 0,
            severity=severity,
            description="Resource has cross-account trust relationships",
            evidence=evidence
        )
    
    def _check_service_trust(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for service trust relationships."""
        evidence = []
        
        service_principals = [
            principal for principal in resource.trust_relationships
            if principal.endswith('.amazonaws.com')
        ]
        
        if service_principals:
            evidence.append(f"Service trust with: {', '.join(service_principals)}")
        
        return RiskFactorAnalysis(
            factor=RiskFactor.SERVICE_TRUST,
            present=len(service_principals) > 0,
            severity=0.2 if service_principals else 0.0,
            description="Resource has service trust relationships",
            evidence=evidence
        )
    
    def _check_broad_resource_access(self, resource: IAMResource) -> RiskFactorAnalysis:
        """Check for broad resource access patterns."""
        evidence = []
        severity = 0.0
        
        for policy in resource.inline_policies:
            if self._policy_has_broad_resources(policy):
                evidence.append("Policy allows access to broad resource patterns")
                severity = max(severity, 0.7)
        
        return RiskFactorAnalysis(
            factor=RiskFactor.BROAD_RESOURCE_ACCESS,
            present=len(evidence) > 0,
            severity=severity,
            description="Resource has broad resource access patterns",
            evidence=evidence
        )
    
    def _policy_has_wildcards(self, policy: Dict[str, Any]) -> bool:
        """Check if a policy document contains wildcard permissions."""
        if not isinstance(policy, dict):
            return False
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            
            # Check actions
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                if isinstance(action, str) and ('*' in action):
                    return True
            
            # Check resources
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            for resource in resources:
                if isinstance(resource, str) and resource == '*':
                    return True
        
        return False
    
    def _policy_has_admin_actions(self, policy: Dict[str, Any]) -> bool:
        """Check if a policy contains administrative actions."""
        if not isinstance(policy, dict):
            return False
        
        admin_actions = [
            'iam:*', '*', 'iam:CreateRole', 'iam:AttachRolePolicy',
            'iam:PutRolePolicy', 'iam:CreateUser', 'iam:AttachUserPolicy'
        ]
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if action in admin_actions:
                        return True
        
        return False
    
    def _policy_has_broad_resources(self, policy: Dict[str, Any]) -> bool:
        """Check if a policy allows access to broad resource patterns."""
        if not isinstance(policy, dict):
            return False
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                
                for resource in resources:
                    if isinstance(resource, str):
                        # Check for overly broad patterns
                        if (resource == '*' or 
                            resource.endswith('/*') or
                            resource.count('*') > 1):
                            return True
        
        return False
    
    def _calculate_structural_risk_score(self, risk_factors: List[RiskFactorAnalysis]) -> float:
        """
        Calculate risk score from structural analysis.
        
        Args:
            risk_factors: List of risk factor analyses
            
        Returns:
            Structural risk score (0.0 to 1.0)
        """
        if not risk_factors:
            return 0.0
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for factor_analysis in risk_factors:
            if factor_analysis.present:
                weight = self.risk_factor_weights.get(factor_analysis.factor, 0.5)
                weighted_score = factor_analysis.severity * weight
                total_weighted_score += weighted_score
                total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        # Normalize by total possible weight
        max_possible_weight = sum(self.risk_factor_weights.values())
        normalized_score = total_weighted_score / max_possible_weight
        
        return min(normalized_score, 1.0)
    
    def _combine_risk_scores(self, keyword_score: float, semantic_score: float, 
                             structural_score: float) -> float:
        """
        Combine different risk scores into final score.
        
        Args:
            keyword_score: Risk score from keyword analysis
            semantic_score: Risk score from semantic analysis
            structural_score: Risk score from structural analysis
            
        Returns:
            Combined final risk score (0.0 to 1.0)
        """
        # Get weights from configuration
        keyword_weight = self.config.path_detection.keyword_weight
        semantic_weight = self.config.path_detection.semantic_weight
        
        # Structural weight is the remainder
        structural_weight = 1.0 - keyword_weight - semantic_weight
        structural_weight = max(0.0, structural_weight)  # Ensure non-negative
        
        # If weights don't sum to 1, normalize them
        total_weight = keyword_weight + semantic_weight + structural_weight
        if total_weight > 0:
            keyword_weight /= total_weight
            semantic_weight /= total_weight
            structural_weight /= total_weight
        
        # Calculate weighted combination
        final_score = (
            keyword_weight * keyword_score +
            semantic_weight * semantic_score +
            structural_weight * structural_score
        )
        
        # Apply non-linear scaling for extreme cases
        if final_score > 0.9:
            # Boost very high scores slightly
            final_score = min(final_score * 1.05, 1.0)
        elif final_score < 0.1:
            # Reduce very low scores slightly
            final_score = max(final_score * 0.8, 0.0)
        
        return min(final_score, 1.0)
    
    def _update_statistics(self, risk_analysis: RiskAnalysis, 
                           risk_factors: List[RiskFactorAnalysis]):
        """Update calculation statistics."""
        self.calculation_stats['resources_analyzed'] += 1
        
        if risk_analysis.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            self.calculation_stats['high_risk_resources'] += 1
        
        # Update risk factor statistics
        for factor in risk_factors:
            if factor.present:
                factor_name = factor.factor.value
                if factor_name not in self.calculation_stats['risk_factors_detected']:
                    self.calculation_stats['risk_factors_detected'][factor_name] = 0
                self.calculation_stats['risk_factors_detected'][factor_name] += 1
        
        # Update average risk score
        total_resources = self.calculation_stats['resources_analyzed']
        current_avg = self.calculation_stats['average_risk_score']
        new_avg = ((current_avg * (total_resources - 1)) + risk_analysis.final_risk_score) / total_resources
        self.calculation_stats['average_risk_score'] = new_avg
    
    def get_calculation_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about risk score calculations.
        
        Returns:
            Dictionary containing calculation statistics
        """
        total_resources = self.calculation_stats['resources_analyzed']
        high_risk_rate = 0.0
        
        if total_resources > 0:
            high_risk_rate = (self.calculation_stats['high_risk_resources'] / total_resources) * 100
        
        return {
            'resources_analyzed': total_resources,
            'high_risk_resources': self.calculation_stats['high_risk_resources'],
            'high_risk_rate': high_risk_rate,
            'average_risk_score': self.calculation_stats['average_risk_score'],
            'risk_factors_detected': dict(self.calculation_stats['risk_factors_detected']),
            'risk_factor_weights': {f.value: w for f, w in self.risk_factor_weights.items()}
        }
    
    def reset_statistics(self):
        """Reset calculation statistics."""
        self.calculation_stats = {
            'resources_analyzed': 0,
            'high_risk_resources': 0,
            'risk_factors_detected': {},
            'average_risk_score': 0.0
        }
        self.logger.info("Reset risk calculation statistics")
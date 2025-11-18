"""
Checkov integration module for hybrid analysis approach.
"""

import subprocess
import json
import logging
from typing import Dict, List, Any
from pathlib import Path


class CheckovIntegration:
    """Integrates Checkov results with NLP analysis for hybrid approach."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def run_checkov_analysis(self, terraform_path: str) -> Dict[str, Any]:
        """Run Checkov analysis and return structured results."""
        try:
            # Run checkov with JSON output
            cmd = [
                "checkov", 
                "-f", terraform_path,
                "--framework", "terraform",
                "--output", "json",
                "--quiet"
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode == 0 or result.returncode == 1:  # 1 means violations found
                # Use text output parsing for reliability
                return self._parse_text_output(result.stdout)
            else:
                self.logger.error(f"Checkov failed: {result.stderr}")
                return {"failed_checks": [], "passed_checks": [], "summary": {}}
                
        except subprocess.TimeoutExpired:
            self.logger.error("Checkov analysis timed out")
            return {"failed_checks": [], "passed_checks": [], "summary": {}}
        except Exception as e:
            self.logger.error(f"Error running Checkov: {e}")
            return {"failed_checks": [], "passed_checks": [], "summary": {}}
    
    def _parse_checkov_results(self, checkov_data: Dict) -> Dict[str, Any]:
        """Parse Checkov JSON results into structured format."""
        results = {
            "failed_checks": [],
            "passed_checks": [],
            "summary": {
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "severity_breakdown": {}
            }
        }
        
        try:
            # Handle different Checkov output formats
            if isinstance(checkov_data, dict):
                if "results" in checkov_data:
                    for result in checkov_data["results"]:
                        if isinstance(result, dict):
                            if "failed_checks" in result:
                                results["failed_checks"].extend(result["failed_checks"])
                            if "passed_checks" in result:
                                results["passed_checks"].extend(result["passed_checks"])
                
                # Direct format (some versions)
                elif "failed_checks" in checkov_data:
                    results["failed_checks"] = checkov_data["failed_checks"]
                elif "passed_checks" in checkov_data:
                    results["passed_checks"] = checkov_data["passed_checks"]
            
            # Calculate summary
            results["summary"]["failed"] = len(results["failed_checks"])
            results["summary"]["passed"] = len(results["passed_checks"])
            results["summary"]["total_checks"] = results["summary"]["failed"] + results["summary"]["passed"]
            
            # Categorize by severity
            severity_counts = {}
            for check in results["failed_checks"]:
                if isinstance(check, dict):
                    severity = self._get_check_severity(check.get("check_id", ""))
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            results["summary"]["severity_breakdown"] = severity_counts
            
        except Exception as e:
            self.logger.error(f"Error parsing Checkov results: {e}")
        
        return results
    
    def _parse_text_output(self, output: str) -> Dict[str, Any]:
        """Parse Checkov text output."""
        lines = output.split('\n')
        failed_checks = []
        passed_checks = []
        
        # Look for summary line
        passed_count = 0
        failed_count = 0
        current_check = None
        
        for line in lines:
            line = line.strip()
            
            # Parse summary line: "Passed checks: 37, Failed checks: 22, Skipped checks: 0"
            if "Passed checks:" in line and "Failed checks:" in line:
                try:
                    # Extract numbers using regex or simple parsing
                    import re
                    passed_match = re.search(r'Passed checks:\s*(\d+)', line)
                    failed_match = re.search(r'Failed checks:\s*(\d+)', line)
                    
                    if passed_match:
                        passed_count = int(passed_match.group(1))
                    if failed_match:
                        failed_count = int(failed_match.group(1))
                except:
                    pass
            
            # Parse individual failed checks
            elif "FAILED for resource:" in line:
                # Extract resource info
                parts = line.split("FAILED for resource:")
                if len(parts) > 1:
                    resource_info = parts[1].strip()
                    failed_checks.append({
                        "resource": resource_info,
                        "check_id": "UNKNOWN",
                        "check_name": "Security violation detected"
                    })
            
            elif line.startswith("Check:"):
                # Extract check ID and description
                check_info = line.replace("Check:", "").strip()
                if ":" in check_info and failed_checks:
                    check_id, description = check_info.split(":", 1)
                    # Update the last failed check
                    failed_checks[-1]["check_id"] = check_id.strip()
                    failed_checks[-1]["check_name"] = description.strip()
        
        # If we couldn't parse individual checks, create summary based on counts
        if not failed_checks and failed_count > 0:
            for i in range(failed_count):
                failed_checks.append({
                    "resource": f"resource_{i+1}",
                    "check_id": "UNKNOWN",
                    "check_name": "Security violation detected"
                })
        
        return {
            "failed_checks": failed_checks,
            "passed_checks": [{"check_id": f"PASS_{i}"} for i in range(passed_count)],
            "summary": {
                "total_checks": passed_count + failed_count,
                "passed": passed_count,
                "failed": failed_count,
                "severity_breakdown": {}
            }
        }
    
    def _get_check_severity(self, check_id: str) -> str:
        """Determine severity based on check ID patterns."""
        high_severity_patterns = [
            "CKV_AWS_274",  # AdministratorAccess
            "CKV_AWS_286",  # Privilege escalation
            "CKV_AWS_287",  # Credentials exposure
            "CKV2_AWS_56",  # IAMFullAccess
        ]
        
        medium_severity_patterns = [
            "CKV_AWS_40",   # Direct policy attachment
            "CKV_AWS_273",  # SSO usage
            "CKV_AWS_289",  # Permission management
        ]
        
        if any(pattern in check_id for pattern in high_severity_patterns):
            return "HIGH"
        elif any(pattern in check_id for pattern in medium_severity_patterns):
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_nlp_analysis_candidates(self, checkov_results: Dict[str, Any]) -> List[str]:
        """Identify resources that need NLP analysis based on Checkov results."""
        candidates = []
        
        for check in checkov_results["failed_checks"]:
            resource = check.get("resource", "")
            check_id = check.get("check_id", "")
            
            # Focus NLP on high-risk items
            if (self._get_check_severity(check_id) in ["HIGH", "MEDIUM"] or
                any(keyword in resource.lower() for keyword in ["user", "role", "policy"])):
                candidates.append(resource)
        
        return list(set(candidates))  # Remove duplicates
    
    def create_hybrid_report(self, checkov_results: Dict[str, Any], 
                           nlp_results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine Checkov and NLP results into comprehensive report."""
        
        hybrid_report = {
            "summary": {
                "checkov_checks": checkov_results["summary"]["total_checks"],
                "checkov_failed": checkov_results["summary"]["failed"],
                "nlp_resources_analyzed": len(nlp_results.get("resources", [])),
                "nlp_additional_findings": 0,
                "total_analysis_time": 0
            },
            "security_findings": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            },
            "recommendations": [],
            "checkov_details": checkov_results,
            "nlp_details": nlp_results
        }
        
        # Categorize Checkov findings
        for check in checkov_results["failed_checks"]:
            severity = self._get_check_severity(check.get("check_id", ""))
            finding = {
                "source": "checkov",
                "type": "policy_violation",
                "check_id": check.get("check_id", ""),
                "description": check.get("check_name", ""),
                "resource": check.get("resource", ""),
                "file_path": check.get("file_path", ""),
                "line_numbers": check.get("file_line_range", [])
            }
            
            if severity == "HIGH":
                hybrid_report["security_findings"]["high"].append(finding)
            elif severity == "MEDIUM":
                hybrid_report["security_findings"]["medium"].append(finding)
            else:
                hybrid_report["security_findings"]["low"].append(finding)
        
        # Add NLP findings
        if "cli_output" in nlp_results:
            nlp_findings = self._extract_nlp_findings(nlp_results["cli_output"])
            for finding in nlp_findings:
                finding["source"] = "nlp"
                hybrid_report["security_findings"][finding["severity"]].append(finding)
                hybrid_report["summary"]["nlp_additional_findings"] += 1
        
        # Generate recommendations
        hybrid_report["recommendations"] = self._generate_recommendations(hybrid_report)
        
        return hybrid_report
    
    def _extract_nlp_findings(self, cli_output: str) -> List[Dict[str, Any]]:
        """Extract structured findings from NLP CLI output."""
        findings = []
        lines = cli_output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if "🚨 Found" in line and "users with direct policy attachments" in line:
                findings.append({
                    "type": "structural_risk",
                    "severity": "high",
                    "description": "Users with direct policy attachments (privilege escalation risk)",
                    "details": line
                })
            
            elif "⚠️  Found" in line and "temporary" in line:
                findings.append({
                    "type": "temporal_risk", 
                    "severity": "medium",
                    "description": "Temporary accounts without proper lifecycle management",
                    "details": line
                })
            
            elif "⚠️  Found" in line and "external" in line:
                findings.append({
                    "type": "external_access",
                    "severity": "medium", 
                    "description": "External/vendor users requiring review",
                    "details": line
                })
            
            elif "🔴 Found" in line and "admin" in line:
                findings.append({
                    "type": "privilege_escalation",
                    "severity": "critical",
                    "description": "Users with direct admin-level access",
                    "details": line
                })
        
        return findings
    
    def _generate_recommendations(self, hybrid_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on combined analysis."""
        recommendations = []
        
        # Critical findings
        critical_count = len(hybrid_report["security_findings"]["critical"])
        if critical_count > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "title": f"Address {critical_count} critical security issues immediately",
                "description": "These issues pose immediate security risks and should be resolved within 24 hours",
                "actions": [
                    "Review all admin-level direct access grants",
                    "Implement principle of least privilege",
                    "Add MFA requirements for privileged accounts"
                ]
            })
        
        # High findings
        high_count = len(hybrid_report["security_findings"]["high"])
        if high_count > 0:
            recommendations.append({
                "priority": "HIGH",
                "title": f"Resolve {high_count} high-risk security violations",
                "description": "These violations significantly increase attack surface",
                "actions": [
                    "Replace direct user policy attachments with role-based access",
                    "Implement IAM groups for user management",
                    "Review and restrict overprivileged policies"
                ]
            })
        
        # Structural improvements
        if any("direct policy attachments" in str(finding) for finding in 
               hybrid_report["security_findings"]["high"] + hybrid_report["security_findings"]["medium"]):
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Implement role-based access control",
                "description": "Move from direct user policy attachments to role-based access",
                "actions": [
                    "Create IAM roles for common access patterns",
                    "Use IAM groups for user categorization", 
                    "Implement assume-role patterns for applications"
                ]
            })
        
        return recommendations
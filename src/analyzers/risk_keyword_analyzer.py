"""
IAM 리소스를 위한 위험 키워드 분석

이 모듈은 설정 가능한 키워드 사전과 패턴 매칭 알고리즘을 사용하여
키워드 기반 위험 분석을 구현합니다.
"""

import re
import logging
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass
from collections import defaultdict

from config.settings import Config


@dataclass
class KeywordMatch:
    """컨텍스트 정보와 함께 키워드 매치를 나타냅니다."""
    keyword: str
    matched_text: str
    position: int
    context: str
    weight: float
    match_type: str  # '정확', '퍼지', '정규식'


class RiskKeywordAnalyzer:
    """
    위험 관련 키워드와 패턴에 대한 텍스트 내용을 분석합니다.
    
    정확한 매칭, 퍼지 매칭, 정규식 패턴을 지원하는 
    설정 가능한 키워드 매칭을 제공합니다.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the risk keyword analyzer.
        
        Args:
            config: Configuration object containing keyword settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load risk keywords from configuration
        self.risk_keywords = config.nlp.risk_keywords.copy()
        
        # Compile regex patterns for efficient matching
        self._compiled_patterns = {}
        self._prepare_patterns()
        
        # Statistics tracking
        self.analysis_stats = {
            'texts_analyzed': 0,
            'keywords_matched': 0,
            'matches_by_keyword': defaultdict(int),
            'matches_by_type': defaultdict(int)
        }
    
    def analyze_keyword_risk(self, text: str) -> Tuple[float, List[str]]:
        """
        Analyze risk based on keyword matching.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, matched_keywords)
        """
        if not text or not isinstance(text, str):
            return 0.0, []
        
        self.logger.debug(f"Analyzing keyword risk for text: {text[:100]}...")
        
        # Find all keyword matches
        matches = self._find_keyword_matches(text)
        
        # Calculate risk score
        risk_score = self._calculate_keyword_risk_score(matches)
        
        # Extract matched keywords
        matched_keywords = list(set(match.keyword for match in matches))
        
        # Update statistics
        self.analysis_stats['texts_analyzed'] += 1
        self.analysis_stats['keywords_matched'] += len(matches)
        
        for match in matches:
            self.analysis_stats['matches_by_keyword'][match.keyword] += 1
            self.analysis_stats['matches_by_type'][match.match_type] += 1
        
        self.logger.debug(f"Found {len(matches)} keyword matches, risk score: {risk_score:.3f}")
        
        return risk_score, matched_keywords
    
    def analyze_detailed_keyword_risk(self, text: str) -> Tuple[float, List[KeywordMatch]]:
        """
        Analyze risk with detailed match information.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, keyword_matches)
        """
        if not text or not isinstance(text, str):
            return 0.0, []
        
        # Find all keyword matches with details
        matches = self._find_keyword_matches(text)
        
        # Calculate risk score
        risk_score = self._calculate_keyword_risk_score(matches)
        
        return risk_score, matches
    
    def _find_keyword_matches(self, text: str) -> List[KeywordMatch]:
        """
        Find all keyword matches in the text.
        
        Args:
            text: Text to search
            
        Returns:
            List of KeywordMatch objects
        """
        matches = []
        text_lower = text.lower()
        
        # Exact keyword matching
        matches.extend(self._find_exact_matches(text, text_lower))
        
        # Fuzzy matching (if enabled)
        if hasattr(self.config.nlp, 'enable_fuzzy_matching') and self.config.nlp.enable_fuzzy_matching:
            matches.extend(self._find_fuzzy_matches(text, text_lower))
        
        # Regex pattern matching
        matches.extend(self._find_regex_matches(text, text_lower))
        
        # Remove duplicates and sort by position
        unique_matches = self._deduplicate_matches(matches)
        
        return sorted(unique_matches, key=lambda m: m.position)
    
    def _find_exact_matches(self, text: str, text_lower: str) -> List[KeywordMatch]:
        """Find exact keyword matches."""
        matches = []
        
        for keyword, weight in self.risk_keywords.items():
            keyword_lower = keyword.lower()
            
            # Find all occurrences of the keyword
            start = 0
            while True:
                pos = text_lower.find(keyword_lower, start)
                if pos == -1:
                    break
                
                # Check word boundaries to avoid partial matches
                if self._is_word_boundary_match(text_lower, keyword_lower, pos):
                    context = self._extract_context(text, pos, len(keyword))
                    
                    match = KeywordMatch(
                        keyword=keyword,
                        matched_text=text[pos:pos + len(keyword)],
                        position=pos,
                        context=context,
                        weight=weight,
                        match_type='exact'
                    )
                    matches.append(match)
                
                start = pos + 1
        
        return matches
    
    def _find_fuzzy_matches(self, text: str, text_lower: str) -> List[KeywordMatch]:
        """Find fuzzy keyword matches (with small variations)."""
        matches = []
        
        # Simple fuzzy matching - look for keywords with common variations
        fuzzy_patterns = {
            'admin': ['adm', 'administrator', 'administration'],
            'temp': ['temporary', 'tmp'],
            'test': ['testing', 'tester'],
            'dev': ['development', 'developer'],
            'debug': ['debugging', 'debugger']
        }
        
        for base_keyword, variations in fuzzy_patterns.items():
            if base_keyword in self.risk_keywords:
                base_weight = self.risk_keywords[base_keyword]
                
                for variation in variations:
                    variation_lower = variation.lower()
                    start = 0
                    
                    while True:
                        pos = text_lower.find(variation_lower, start)
                        if pos == -1:
                            break
                        
                        if self._is_word_boundary_match(text_lower, variation_lower, pos):
                            context = self._extract_context(text, pos, len(variation))
                            
                            # Reduce weight for fuzzy matches
                            fuzzy_weight = base_weight * 0.8
                            
                            match = KeywordMatch(
                                keyword=base_keyword,
                                matched_text=text[pos:pos + len(variation)],
                                position=pos,
                                context=context,
                                weight=fuzzy_weight,
                                match_type='fuzzy'
                            )
                            matches.append(match)
                        
                        start = pos + 1
        
        return matches
    
    def _find_regex_matches(self, text: str, text_lower: str) -> List[KeywordMatch]:
        """Find matches using regex patterns."""
        matches = []
        
        # Define regex patterns for common risky patterns
        regex_patterns = {
            'wildcard_permissions': (r'\*', 0.9),  # Wildcard in permissions
            'admin_suffix': (r'\w*admin\w*', 0.8),  # Words containing 'admin'
            'root_access': (r'\broot\b', 0.95),  # Root access
            'full_access': (r'\bfull\s+access\b', 0.85),  # Full access phrases
            'bypass_pattern': (r'\b(bypass|override|skip)\b', 0.8),  # Bypass patterns
            'emergency_access': (r'\b(emergency|urgent|critical)\s+(access|role|user)\b', 0.75)
        }
        
        for pattern_name, (pattern, weight) in regex_patterns.items():
            if pattern_name not in self._compiled_patterns:
                try:
                    self._compiled_patterns[pattern_name] = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    self.logger.warning(f"Invalid regex pattern: {pattern}")
                    continue
            
            compiled_pattern = self._compiled_patterns[pattern_name]
            
            for match in compiled_pattern.finditer(text):
                context = self._extract_context(text, match.start(), match.end() - match.start())
                
                keyword_match = KeywordMatch(
                    keyword=pattern_name,
                    matched_text=match.group(),
                    position=match.start(),
                    context=context,
                    weight=weight,
                    match_type='regex'
                )
                matches.append(keyword_match)
        
        return matches
    
    def _is_word_boundary_match(self, text: str, keyword: str, position: int) -> bool:
        """
        Check if a keyword match respects word boundaries.
        
        Args:
            text: Full text
            keyword: Keyword that was matched
            position: Position of the match
            
        Returns:
            True if the match is at word boundaries
        """
        # Check character before the match
        if position > 0:
            char_before = text[position - 1]
            if char_before.isalnum() or char_before == '_':
                return False
        
        # Check character after the match
        end_pos = position + len(keyword)
        if end_pos < len(text):
            char_after = text[end_pos]
            if char_after.isalnum() or char_after == '_':
                return False
        
        return True
    
    def _extract_context(self, text: str, position: int, length: int, context_size: int = 30) -> str:
        """
        Extract context around a keyword match.
        
        Args:
            text: Full text
            position: Position of the match
            length: Length of the matched text
            context_size: Number of characters to include on each side
            
        Returns:
            Context string
        """
        start = max(0, position - context_size)
        end = min(len(text), position + length + context_size)
        
        context = text[start:end]
        
        # Add ellipsis if we truncated
        if start > 0:
            context = '...' + context
        if end < len(text):
            context = context + '...'
        
        return context.strip()
    
    def _calculate_keyword_risk_score(self, matches: List[KeywordMatch]) -> float:
        """
        Calculate overall risk score from keyword matches.
        
        Args:
            matches: List of keyword matches
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        if not matches:
            return 0.0
        
        # Calculate weighted score
        total_weight = 0.0
        unique_keywords = set()
        
        for match in matches:
            # Avoid double-counting the same keyword
            if match.keyword not in unique_keywords:
                total_weight += match.weight
                unique_keywords.add(match.keyword)
            else:
                # Reduced weight for additional occurrences
                total_weight += match.weight * 0.3
        
        # Apply diminishing returns for multiple keywords
        num_unique = len(unique_keywords)
        if num_unique > 1:
            # Bonus for multiple different risk keywords
            multiplier = min(1.0 + (num_unique - 1) * 0.1, 1.5)
            total_weight *= multiplier
        
        # Normalize to 0-1 range
        # Assume maximum possible weight is around 3.0 for very risky content
        normalized_score = min(total_weight / 3.0, 1.0)
        
        return normalized_score
    
    def _deduplicate_matches(self, matches: List[KeywordMatch]) -> List[KeywordMatch]:
        """
        Remove duplicate matches that overlap significantly.
        
        Args:
            matches: List of keyword matches
            
        Returns:
            Deduplicated list of matches
        """
        if not matches:
            return matches
        
        # Sort by position
        sorted_matches = sorted(matches, key=lambda m: m.position)
        
        deduplicated = []
        
        for match in sorted_matches:
            # Check if this match overlaps significantly with any existing match
            overlaps = False
            
            for existing in deduplicated:
                # Calculate overlap
                match_end = match.position + len(match.matched_text)
                existing_end = existing.position + len(existing.matched_text)
                
                overlap_start = max(match.position, existing.position)
                overlap_end = min(match_end, existing_end)
                
                if overlap_end > overlap_start:
                    overlap_length = overlap_end - overlap_start
                    match_length = len(match.matched_text)
                    existing_length = len(existing.matched_text)
                    
                    # If overlap is more than 50% of either match, consider it a duplicate
                    if (overlap_length / match_length > 0.5 or 
                        overlap_length / existing_length > 0.5):
                        overlaps = True
                        break
            
            if not overlaps:
                deduplicated.append(match)
        
        return deduplicated
    
    def _prepare_patterns(self):
        """Prepare and compile regex patterns for efficient matching."""
        # Pre-compile common patterns
        common_patterns = {
            'word_boundary': r'\b',
            'wildcard': r'\*+',
            'admin_variants': r'\b(admin|administrator|administration)\b'
        }
        
        for name, pattern in common_patterns.items():
            try:
                self._compiled_patterns[name] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                self.logger.warning(f"Failed to compile pattern {name}: {e}")
    
    def add_custom_keyword(self, keyword: str, weight: float):
        """
        Add a custom risk keyword.
        
        Args:
            keyword: Keyword to add
            weight: Risk weight (0.0 to 1.0)
        """
        if not isinstance(keyword, str) or not keyword.strip():
            raise ValueError("Keyword must be a non-empty string")
        
        if not 0.0 <= weight <= 1.0:
            raise ValueError("Weight must be between 0.0 and 1.0")
        
        self.risk_keywords[keyword.strip().lower()] = weight
        self.logger.info(f"Added custom keyword: {keyword} (weight: {weight})")
    
    def remove_keyword(self, keyword: str):
        """
        Remove a risk keyword.
        
        Args:
            keyword: Keyword to remove
        """
        keyword_lower = keyword.lower()
        if keyword_lower in self.risk_keywords:
            del self.risk_keywords[keyword_lower]
            self.logger.info(f"Removed keyword: {keyword}")
        else:
            self.logger.warning(f"Keyword not found: {keyword}")
    
    def update_keyword_weight(self, keyword: str, new_weight: float):
        """
        Update the weight of an existing keyword.
        
        Args:
            keyword: Keyword to update
            new_weight: New weight value
        """
        if not 0.0 <= new_weight <= 1.0:
            raise ValueError("Weight must be between 0.0 and 1.0")
        
        keyword_lower = keyword.lower()
        if keyword_lower in self.risk_keywords:
            old_weight = self.risk_keywords[keyword_lower]
            self.risk_keywords[keyword_lower] = new_weight
            self.logger.info(f"Updated keyword {keyword}: {old_weight} -> {new_weight}")
        else:
            self.logger.warning(f"Keyword not found: {keyword}")
    
    def get_keyword_statistics(self) -> Dict[str, any]:
        """
        Get statistics about keyword analysis.
        
        Returns:
            Dictionary containing analysis statistics
        """
        return {
            'total_keywords': len(self.risk_keywords),
            'texts_analyzed': self.analysis_stats['texts_analyzed'],
            'total_matches': self.analysis_stats['keywords_matched'],
            'matches_by_keyword': dict(self.analysis_stats['matches_by_keyword']),
            'matches_by_type': dict(self.analysis_stats['matches_by_type']),
            'average_matches_per_text': (
                self.analysis_stats['keywords_matched'] / 
                max(1, self.analysis_stats['texts_analyzed'])
            )
        }
    
    def reset_statistics(self):
        """Reset analysis statistics."""
        self.analysis_stats = {
            'texts_analyzed': 0,
            'keywords_matched': 0,
            'matches_by_keyword': defaultdict(int),
            'matches_by_type': defaultdict(int)
        }
        self.logger.info("Reset keyword analysis statistics")
    
    def export_keywords(self) -> Dict[str, float]:
        """
        Export current keyword configuration.
        
        Returns:
            Dictionary of keywords and their weights
        """
        return self.risk_keywords.copy()
    
    def import_keywords(self, keywords: Dict[str, float], replace: bool = False):
        """
        Import keyword configuration.
        
        Args:
            keywords: Dictionary of keywords and weights
            replace: If True, replace existing keywords; if False, merge
        """
        if replace:
            self.risk_keywords.clear()
        
        for keyword, weight in keywords.items():
            if not isinstance(keyword, str) or not keyword.strip():
                self.logger.warning(f"Skipping invalid keyword: {keyword}")
                continue
            
            if not isinstance(weight, (int, float)) or not 0.0 <= weight <= 1.0:
                self.logger.warning(f"Skipping keyword {keyword} with invalid weight: {weight}")
                continue
            
            self.risk_keywords[keyword.strip().lower()] = float(weight)
        
        self.logger.info(f"Imported {len(keywords)} keywords (replace={replace})")
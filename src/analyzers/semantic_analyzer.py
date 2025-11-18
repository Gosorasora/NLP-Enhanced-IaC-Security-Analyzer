"""
위험도 평가를 위한 BERT 모델 기반 의미론적 분석

이 모듈은 사전 훈련된 BERT 모델을 사용하여 리소스 텍스트와 
위험 개념 간의 유사도를 측정하는 의미론적 유사도 분석을 구현합니다.
"""

import logging
import pickle
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import numpy as np

try:
    from transformers import AutoTokenizer, AutoModel
    import torch
    import torch.nn.functional as F
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    AutoTokenizer = None
    AutoModel = None
    torch = None
    F = None

from config.settings import Config


@dataclass
class SemanticSimilarity:
    """텍스트와 위험 개념 간의 의미론적 유사도를 나타냅니다."""
    concept: str
    similarity_score: float
    text_embedding: Optional[np.ndarray] = None
    concept_embedding: Optional[np.ndarray] = None


class SemanticAnalyzer:
    """
    BERT 모델을 사용하는 의미론적 위험 분석기
    
    트랜스포머 기반 임베딩을 사용하여 리소스 텍스트 내용과
    사전 정의된 위험 개념 간의 의미론적 유사도를 계산합니다.
    """
    
    def __init__(self, config: Config):
        """
        의미론적 분석기를 초기화합니다.
        
        Args:
            config: NLP 설정을 포함하는 설정 객체
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        if not TRANSFORMERS_AVAILABLE:
            self.logger.error(
                "Transformers library not available. "
                "Install with: pip install transformers torch"
            )
            raise ImportError("transformers and torch are required for semantic analysis")
        
        # Model and tokenizer
        self.model = None
        self.tokenizer = None
        self.device = None
        
        # Risk concepts from configuration
        self.risk_concepts = config.nlp.risk_concepts.copy()
        
        # Embedding cache
        self.embedding_cache = {}
        self.cache_file = Path('.cache/semantic_embeddings.pkl')
        
        # Pre-computed concept embeddings
        self.concept_embeddings = {}
        
        # Statistics
        self.analysis_stats = {
            'texts_analyzed': 0,
            'similarities_computed': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Initialize model
        self._initialize_model()
        
        # Pre-compute concept embeddings
        self._precompute_concept_embeddings()
    
    def _initialize_model(self):
        """Initialize the BERT model and tokenizer."""
        try:
            model_name = self.config.nlp.model_name
            self.logger.info(f"Loading BERT model: {model_name}")
            
            # Load tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModel.from_pretrained(model_name)
            
            # Set device
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            self.model.to(self.device)
            self.model.eval()  # Set to evaluation mode
            
            self.logger.info(f"Model loaded successfully on device: {self.device}")
            
            # Load embedding cache if it exists
            self._load_embedding_cache()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize BERT model: {str(e)}")
            raise
    
    def analyze_semantic_risk(self, text: str) -> Tuple[float, Dict[str, float]]:
        """
        Analyze risk using semantic similarity with risk concepts.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, similarity_scores_by_concept)
        """
        if not text or not isinstance(text, str):
            return 0.0, {}
        
        self.logger.debug(f"Analyzing semantic risk for text: {text[:100]}...")
        
        # Get text embedding
        text_embedding = self._get_text_embedding(text)
        
        # Calculate similarities with all risk concepts
        similarities = {}
        
        for concept in self.risk_concepts:
            if concept in self.concept_embeddings:
                concept_embedding = self.concept_embeddings[concept]
                similarity = self._calculate_cosine_similarity(text_embedding, concept_embedding)
                similarities[concept] = float(similarity)
                
                self.analysis_stats['similarities_computed'] += 1
        
        # Calculate overall risk score
        risk_score = self._calculate_semantic_risk_score(similarities)
        
        # Update statistics
        self.analysis_stats['texts_analyzed'] += 1
        
        self.logger.debug(f"Semantic analysis complete. Risk score: {risk_score:.3f}")
        
        return risk_score, similarities
    
    def analyze_detailed_semantic_risk(self, text: str) -> Tuple[float, List[SemanticSimilarity]]:
        """
        Analyze semantic risk with detailed similarity information.
        
        Args:
            text: Text content to analyze
            
        Returns:
            Tuple of (risk_score, semantic_similarities)
        """
        if not text or not isinstance(text, str):
            return 0.0, []
        
        # Get text embedding
        text_embedding = self._get_text_embedding(text)
        
        # Calculate detailed similarities
        similarities = []
        
        for concept in self.risk_concepts:
            if concept in self.concept_embeddings:
                concept_embedding = self.concept_embeddings[concept]
                similarity_score = self._calculate_cosine_similarity(text_embedding, concept_embedding)
                
                similarity = SemanticSimilarity(
                    concept=concept,
                    similarity_score=float(similarity_score),
                    text_embedding=text_embedding,
                    concept_embedding=concept_embedding
                )
                similarities.append(similarity)
        
        # Calculate overall risk score
        similarity_dict = {s.concept: s.similarity_score for s in similarities}
        risk_score = self._calculate_semantic_risk_score(similarity_dict)
        
        return risk_score, similarities
    
    def batch_analyze_semantic_risk(self, texts: List[str]) -> List[Tuple[float, Dict[str, float]]]:
        """
        Analyze multiple texts in batch for efficiency.
        
        Args:
            texts: List of text strings to analyze
            
        Returns:
            List of (risk_score, similarities) tuples
        """
        if not texts:
            return []
        
        self.logger.info(f"Batch analyzing {len(texts)} texts")
        
        # Get embeddings for all texts in batch
        text_embeddings = self._get_batch_text_embeddings(texts)
        
        results = []
        
        for i, text in enumerate(texts):
            if i < len(text_embeddings):
                text_embedding = text_embeddings[i]
                
                # Calculate similarities
                similarities = {}
                for concept in self.risk_concepts:
                    if concept in self.concept_embeddings:
                        concept_embedding = self.concept_embeddings[concept]
                        similarity = self._calculate_cosine_similarity(text_embedding, concept_embedding)
                        similarities[concept] = float(similarity)
                
                # Calculate risk score
                risk_score = self._calculate_semantic_risk_score(similarities)
                results.append((risk_score, similarities))
            else:
                # Fallback for failed embeddings
                results.append((0.0, {}))
        
        self.analysis_stats['texts_analyzed'] += len(texts)
        
        return results
    
    def _get_text_embedding(self, text: str) -> np.ndarray:
        """
        Get BERT embedding for a text string.
        
        Args:
            text: Input text
            
        Returns:
            Numpy array containing the text embedding
        """
        # Check cache first
        cache_key = self._get_cache_key(text)
        
        if cache_key in self.embedding_cache:
            self.analysis_stats['cache_hits'] += 1
            return self.embedding_cache[cache_key]
        
        self.analysis_stats['cache_misses'] += 1
        
        try:
            # Tokenize text
            inputs = self.tokenizer(
                text,
                return_tensors='pt',
                truncation=True,
                padding=True,
                max_length=self.config.nlp.max_sequence_length
            )
            
            # Move to device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Get embeddings
            with torch.no_grad():
                outputs = self.model(**inputs)
                
                # Use [CLS] token embedding (first token)
                cls_embedding = outputs.last_hidden_state[:, 0, :].cpu().numpy()
                
                # Alternatively, use mean pooling of all tokens
                # attention_mask = inputs['attention_mask']
                # token_embeddings = outputs.last_hidden_state
                # input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
                # sum_embeddings = torch.sum(token_embeddings * input_mask_expanded, 1)
                # sum_mask = torch.clamp(input_mask_expanded.sum(1), min=1e-9)
                # cls_embedding = (sum_embeddings / sum_mask).cpu().numpy()
            
            embedding = cls_embedding[0]  # Remove batch dimension
            
            # Cache the result
            if self.config.nlp.cache_predictions:
                self.embedding_cache[cache_key] = embedding
            
            return embedding
            
        except Exception as e:
            self.logger.error(f"Failed to get embedding for text: {str(e)}")
            # Return zero embedding as fallback
            return np.zeros(768)  # BERT base hidden size
    
    def _get_batch_text_embeddings(self, texts: List[str]) -> List[np.ndarray]:
        """
        Get embeddings for multiple texts in batch.
        
        Args:
            texts: List of text strings
            
        Returns:
            List of numpy arrays containing embeddings
        """
        try:
            # Check cache for all texts
            embeddings = []
            uncached_texts = []
            uncached_indices = []
            
            for i, text in enumerate(texts):
                cache_key = self._get_cache_key(text)
                if cache_key in self.embedding_cache:
                    embeddings.append(self.embedding_cache[cache_key])
                    self.analysis_stats['cache_hits'] += 1
                else:
                    embeddings.append(None)  # Placeholder
                    uncached_texts.append(text)
                    uncached_indices.append(i)
                    self.analysis_stats['cache_misses'] += 1
            
            # Process uncached texts in batch
            if uncached_texts:
                # Tokenize all uncached texts
                inputs = self.tokenizer(
                    uncached_texts,
                    return_tensors='pt',
                    truncation=True,
                    padding=True,
                    max_length=self.config.nlp.max_sequence_length
                )
                
                # Move to device
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                # Get embeddings
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    
                    # Use [CLS] token embeddings
                    cls_embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
                
                # Fill in the uncached embeddings
                for i, embedding in enumerate(cls_embeddings):
                    original_index = uncached_indices[i]
                    embeddings[original_index] = embedding
                    
                    # Cache the result
                    if self.config.nlp.cache_predictions:
                        cache_key = self._get_cache_key(uncached_texts[i])
                        self.embedding_cache[cache_key] = embedding
            
            return embeddings
            
        except Exception as e:
            self.logger.error(f"Failed to get batch embeddings: {str(e)}")
            # Return zero embeddings as fallback
            return [np.zeros(768) for _ in texts]
    
    def _precompute_concept_embeddings(self):
        """Pre-compute embeddings for all risk concepts."""
        self.logger.info("Pre-computing embeddings for risk concepts")
        
        for concept in self.risk_concepts:
            try:
                embedding = self._get_text_embedding(concept)
                self.concept_embeddings[concept] = embedding
                self.logger.debug(f"Computed embedding for concept: {concept}")
            except Exception as e:
                self.logger.error(f"Failed to compute embedding for concept '{concept}': {str(e)}")
        
        self.logger.info(f"Pre-computed {len(self.concept_embeddings)} concept embeddings")
    
    def _calculate_cosine_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Calculate cosine similarity between two embeddings.
        
        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector
            
        Returns:
            Cosine similarity score (-1 to 1)
        """
        try:
            # Normalize vectors
            norm1 = np.linalg.norm(embedding1)
            norm2 = np.linalg.norm(embedding2)
            
            if norm1 == 0 or norm2 == 0:
                return 0.0
            
            # Calculate cosine similarity
            similarity = np.dot(embedding1, embedding2) / (norm1 * norm2)
            
            # Clamp to valid range
            return float(np.clip(similarity, -1.0, 1.0))
            
        except Exception as e:
            self.logger.error(f"Failed to calculate cosine similarity: {str(e)}")
            return 0.0
    
    def _calculate_semantic_risk_score(self, similarities: Dict[str, float]) -> float:
        """
        Calculate overall semantic risk score from concept similarities.
        
        Args:
            similarities: Dictionary of concept -> similarity scores
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        if not similarities:
            return 0.0
        
        # Filter similarities above threshold
        threshold = self.config.nlp.semantic_similarity_threshold
        significant_similarities = [
            score for score in similarities.values() 
            if score >= threshold
        ]
        
        if not significant_similarities:
            return 0.0
        
        # Calculate risk score using different strategies
        
        # Strategy 1: Maximum similarity
        max_similarity = max(significant_similarities)
        
        # Strategy 2: Average of significant similarities
        avg_similarity = sum(significant_similarities) / len(significant_similarities)
        
        # Strategy 3: Weighted combination
        # Give more weight to maximum similarity but consider breadth
        breadth_factor = min(len(significant_similarities) / len(self.risk_concepts), 1.0)
        
        # Combine strategies
        risk_score = (
            0.6 * max_similarity +
            0.3 * avg_similarity +
            0.1 * breadth_factor
        )
        
        # Normalize to 0-1 range (similarities are already -1 to 1, but we want 0-1 for risk)
        # Convert from [-1, 1] to [0, 1]
        normalized_score = (risk_score + 1) / 2
        
        return float(np.clip(normalized_score, 0.0, 1.0))
    
    def _get_cache_key(self, text: str) -> str:
        """
        Generate a cache key for text.
        
        Args:
            text: Input text
            
        Returns:
            Cache key string
        """
        # Use hash of text + model name for cache key
        content = f"{self.config.nlp.model_name}:{text}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _load_embedding_cache(self):
        """Load embedding cache from disk."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'rb') as f:
                    self.embedding_cache = pickle.load(f)
                self.logger.info(f"Loaded {len(self.embedding_cache)} cached embeddings")
        except Exception as e:
            self.logger.warning(f"Failed to load embedding cache: {str(e)}")
            self.embedding_cache = {}
    
    def _save_embedding_cache(self):
        """Save embedding cache to disk."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.embedding_cache, f)
            self.logger.info(f"Saved {len(self.embedding_cache)} embeddings to cache")
        except Exception as e:
            self.logger.warning(f"Failed to save embedding cache: {str(e)}")
    
    def add_risk_concept(self, concept: str):
        """
        Add a new risk concept.
        
        Args:
            concept: Risk concept text to add
        """
        if concept not in self.risk_concepts:
            self.risk_concepts.append(concept)
            
            # Compute embedding for new concept
            try:
                embedding = self._get_text_embedding(concept)
                self.concept_embeddings[concept] = embedding
                self.logger.info(f"Added risk concept: {concept}")
            except Exception as e:
                self.logger.error(f"Failed to add risk concept '{concept}': {str(e)}")
    
    def remove_risk_concept(self, concept: str):
        """
        Remove a risk concept.
        
        Args:
            concept: Risk concept to remove
        """
        if concept in self.risk_concepts:
            self.risk_concepts.remove(concept)
            
            if concept in self.concept_embeddings:
                del self.concept_embeddings[concept]
            
            self.logger.info(f"Removed risk concept: {concept}")
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about semantic analysis.
        
        Returns:
            Dictionary containing analysis statistics
        """
        cache_hit_rate = 0.0
        if self.analysis_stats['cache_hits'] + self.analysis_stats['cache_misses'] > 0:
            cache_hit_rate = (
                self.analysis_stats['cache_hits'] / 
                (self.analysis_stats['cache_hits'] + self.analysis_stats['cache_misses'])
            ) * 100
        
        return {
            'model_name': self.config.nlp.model_name,
            'device': str(self.device),
            'risk_concepts_count': len(self.risk_concepts),
            'texts_analyzed': self.analysis_stats['texts_analyzed'],
            'similarities_computed': self.analysis_stats['similarities_computed'],
            'cache_size': len(self.embedding_cache),
            'cache_hit_rate': cache_hit_rate,
            'cache_hits': self.analysis_stats['cache_hits'],
            'cache_misses': self.analysis_stats['cache_misses']
        }
    
    def clear_cache(self):
        """Clear the embedding cache."""
        self.embedding_cache.clear()
        self.logger.info("Cleared embedding cache")
    
    def save_cache(self):
        """Save the current cache to disk."""
        self._save_embedding_cache()
    
    def __del__(self):
        """Destructor to save cache when object is destroyed."""
        if hasattr(self, 'embedding_cache') and self.config.nlp.cache_predictions:
            try:
                self._save_embedding_cache()
            except:
                pass  # Ignore errors during cleanup
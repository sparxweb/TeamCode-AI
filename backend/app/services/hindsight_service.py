import logging
import re
import time
from typing import List, Tuple, Optional, Dict, Any
import httpx
from app.config import settings
from app.models import MemoryItem

logger = logging.getLogger("teamcode.hindsight")


def normalize_text_for_comparison(text: str) -> str:
    """Normalizes text by lowercasing, stripping punctuation, and collapsing whitespace."""
    cleaned = re.sub(r"[^\w\s]", "", text.lower())
    return " ".join(cleaned.split())


def compute_memory_similarity(text1: str, text2: str) -> float:
    """
    Computes a reliable similarity ratio between two memory strings.
    Handles exact normalized equality, word-token Jaccard, and substring containment.
    """
    norm1 = normalize_text_for_comparison(text1)
    norm2 = normalize_text_for_comparison(text2)
    if norm1 == norm2:
        return 1.0

    words1 = set(norm1.split())
    words2 = set(norm2.split())
    if not words1 or not words2:
        return 0.0

    jaccard = len(words1 & words2) / len(words1 | words2)

    # Substring containment check for near-identical statements with minor prefix/suffix differences
    if len(norm1) > 20 and len(norm2) > 20:
        len_ratio = min(len(norm1), len(norm2)) / max(len(norm1), len(norm2))
        if (norm1 in norm2 or norm2 in norm1) and len_ratio >= 0.75:
            return max(jaccard, 0.90)

    return jaccard


def compute_relevance_score(text: str, tags: List[str], query: str) -> Tuple[float, bool]:
    """
    Computes a realistic relevance score (0.0 - 1.0) and determines whether the memory is relevant.
    Prevents unrelated memories from polluting the review context.
    """
    query_lower = query.lower()
    query_tokens = set(re.findall(r"\b\w{3,}\b", query_lower))
    content_tokens = set(re.findall(r"\b\w{3,}\b", text.lower()))

    # Domain keywords denoting high-signal technical areas
    domain_words = {
        "query", "queries", "sql", "db", "database", "parameter", "parameterized",
        "password", "auth", "token", "secret", "credentials", "encryption",
        "error", "exception", "logging", "logger", "security", "injection",
        "sanitize", "orm", "validation", "rest", "endpoint", "api"
    }

    # Tag matches (excluding overly generic language-only tags)
    tag_matches = [
        t for t in tags
        if t.lower() in query_lower and t.lower() not in {"python", "javascript", "typescript", "code", "rule", "standard"}
    ]
    overlap = query_tokens.intersection(content_tokens)
    domain_overlap = overlap.intersection(domain_words)

    # Determine if truly relevant
    is_relevant = False
    if len(tag_matches) > 0 or len(domain_overlap) > 0:
        is_relevant = True
    elif len(overlap) >= 3:
        is_relevant = True

    if not is_relevant:
        return 0.0, False

    # Score calculation
    score = 0.50
    score += len(tag_matches) * 0.15
    score += len(domain_overlap) * 0.12
    score += min(0.20, len(overlap) * 0.04)

    final_score = min(0.98, max(0.50, round(score, 2)))
    return final_score, True


def deduplicate_and_rank_memories(
    memories: List[MemoryItem],
    query: str,
    max_items: int = 5,
    similarity_threshold: float = 0.80,
) -> List[MemoryItem]:
    """
    Deduplicates identical or near-identical memories while preserving genuinely different rules.
    Prefers the highest-relevance memory when duplicates exist and retains full provenance.
    """
    if not memories:
        return []

    # Sort candidates by relevance score descending so best instances are preferred
    candidates = sorted(memories, key=lambda m: (m.relevance_score or 0.0), reverse=True)

    unique_memories: List[MemoryItem] = []
    for candidate in candidates:
        duplicate_found = False
        for existing in unique_memories:
            sim = compute_memory_similarity(existing.text, candidate.text)
            if sim >= similarity_threshold:
                duplicate_found = True
                # Merge tags from candidate into existing to retain all metadata
                existing_tags = set(existing.tags or [])
                candidate_tags = set(candidate.tags or [])
                existing.tags = list(existing_tags | candidate_tags)
                # Ensure highest relevance score is kept
                if (candidate.relevance_score or 0) > (existing.relevance_score or 0):
                    existing.relevance_score = candidate.relevance_score
                break

        if not duplicate_found:
            unique_memories.append(candidate)

    # Limit to top most relevant memories
    return unique_memories[:max_items]


class HindsightService:
    def __init__(self):
        self._headers: Dict[str, str] = {}
        self._setup_client()
        self._last_health_check_time: float = 0.0
        self._cached_available: Optional[Tuple[bool, str]] = None
        self._health_ttl: float = 15.0

    def _setup_client(self):
        """Initializes authorization headers for Hindsight Cloud."""
        if settings.is_hindsight_configured:
            self._headers = {
                "Authorization": f"Bearer {settings.HINDSIGHT_API_KEY}",
                "Content-Type": "application/json",
            }
        else:
            self._headers = {}

    def is_available(self, force: bool = False) -> Tuple[bool, str]:
        """
        Performs a real live connectivity test against Hindsight Cloud
        to verify that the API key is valid and the team bank exists.
        Caches result with short TTL to avoid redundant network overhead.
        """
        if not settings.is_hindsight_configured:
            return False, "HINDSIGHT_API_KEY is missing in .env."

        now = time.time()
        if not force and self._cached_available is not None and (now - self._last_health_check_time < self._health_ttl):
            return self._cached_available

        try:
            url = f"{settings.HINDSIGHT_BASE_URL}/v1/default/banks/{settings.HINDSIGHT_BANK_ID}/directives"
            with httpx.Client(timeout=10.0) as client:
                res = client.get(
                    url,
                    headers={"Authorization": f"Bearer {settings.HINDSIGHT_API_KEY}"},
                    params={"limit": 1},
                )

            if res.status_code == 200:
                result = (True, f"Connected to bank '{settings.HINDSIGHT_BANK_ID}'")
            elif res.status_code in (401, 403):
                result = (False, f"Hindsight authentication failed ({res.status_code})")
            elif res.status_code == 404:
                result = (False, f"Hindsight bank '{settings.HINDSIGHT_BANK_ID}' not found")
            else:
                result = (False, f"Hindsight returned status {res.status_code}")
        except Exception as e:
            err_str = str(e)
            logger.warning("Hindsight live health check failed: %s", err_str)
            result = (False, f"Hindsight unreachable: {err_str}")

        self._cached_available = result
        self._last_health_check_time = now
        return result

    def retain(
        self,
        content: str,
        context: Optional[str] = None,
        tags: Optional[List[str]] = None,
        memory_type: Optional[str] = "Team rule",
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Retains a team rule, architecture decision, or review feedback into Hindsight.
        Stores it directly in the team's Hindsight Cloud bank.
        """
        available, reason = self.is_available()
        if not available:
            return False, {}, reason

        clean_tags = [t.strip().lower() for t in (tags or []) if t.strip()]
        rule_name = f"{memory_type or 'Rule'}: {content[:35]}"

        try:
            url = f"{settings.HINDSIGHT_BASE_URL}/v1/default/banks/{settings.HINDSIGHT_BANK_ID}/directives"
            payload = {
                "name": rule_name,
                "content": content,
                "tags": clean_tags if clean_tags else ["team_standard"],
                "priority": 0,
                "is_active": True,
            }
            with httpx.Client(timeout=15.0) as client:
                res = client.post(
                    url,
                    headers={"Authorization": f"Bearer {settings.HINDSIGHT_API_KEY}"},
                    json=payload,
                )

            if res.status_code in (200, 201):
                data = res.json()
                result_dict = {
                    "success": True,
                    "bank_id": settings.HINDSIGHT_BANK_ID,
                    "operation_id": data.get("id"),
                    "items_count": 1,
                }
                logger.info(
                    "Successfully retained memory in Hindsight bank %s (ID: %s)",
                    settings.HINDSIGHT_BANK_ID,
                    data.get("id"),
                )
                return True, result_dict, None
            else:
                err_msg = f"Hindsight retain returned HTTP {res.status_code}: {res.text}"
                logger.error(err_msg)
                return False, {}, err_msg

        except Exception as e:
            final_err = f"Failed to retain in Hindsight: {str(e)}"
            logger.error(final_err)
            return False, {}, final_err

    def recall(
        self, query: str, max_tokens: int = 4096
    ) -> Tuple[str, List[MemoryItem], str]:
        """
        Recalls relevant team memories from Hindsight.
        Queries the Hindsight bank directly, applies semantic relevance filtering,
        and deduplicates near-identical/duplicate memories.
        Returns:
            status: "recalled" | "none_found" | "unavailable"
            memories: List[MemoryItem]
            message: User-facing explanation
        """
        available, reason = self.is_available()
        if not available:
            return "unavailable", [], f"Hindsight is unavailable: {reason} Review running without memory."

        try:
            url = f"{settings.HINDSIGHT_BASE_URL}/v1/default/banks/{settings.HINDSIGHT_BANK_ID}/directives"
            with httpx.Client(timeout=20.0) as client:
                res = client.get(
                    url,
                    headers={"Authorization": f"Bearer {settings.HINDSIGHT_API_KEY}"},
                )

            if res.status_code != 200:
                logger.error("Hindsight recall returned %s: %s", res.status_code, res.text)
                return "unavailable", [], f"Hindsight returned HTTP {res.status_code}. Review running without memory."

            data = res.json()
            items = data.get("items", []) or []

            if not items:
                return "none_found", [], "No relevant team memory found in Hindsight."

            # Filter candidates by semantic relevance and score them
            candidate_memories: List[MemoryItem] = []
            for d in items:
                content = (d.get("content") or "").strip()
                if not content:
                    continue
                d_tags = [t.lower().strip() for t in (d.get("tags") or []) if t.strip()]
                score, is_rel = compute_relevance_score(content, d_tags, query)
                if not is_rel:
                    continue

                candidate_memories.append(
                    MemoryItem(
                        id=str(d.get("id")),
                        text=content,
                        type=d.get("name", "Team rule"),
                        relevance_score=score,
                        context=f"Retrieved from Hindsight Cloud (Bank: {settings.HINDSIGHT_BANK_ID})",
                        tags=d.get("tags") or [],
                    )
                )

            # Deduplicate near-identical memories and rank by relevance
            unique_memories = deduplicate_and_rank_memories(
                candidate_memories, query=query, max_items=5, similarity_threshold=0.80
            )

            if not unique_memories:
                return "none_found", [], "No relevant team memory found in Hindsight."

            count = len(unique_memories)
            msg = f"{count} relevant team {'memory' if count == 1 else 'memories'} influenced this review."
            return "recalled", unique_memories, msg

        except Exception as e:
            err_msg = str(e)
            logger.error("Hindsight retrieval error: %s", err_msg)
            return "unavailable", [], f"Hindsight recall failed: {err_msg}. Review running without memory."


hindsight_service = HindsightService()

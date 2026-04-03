# engine/analyzer.py
# Phase 2: Brute-force all 26 Caesar shifts and score each result.
#
# Scoring strategy (Phase 2 — simple word matching):
#   We check how many common English words appear in the decoded text.
#   More matches = higher score = more likely to be the correct shift.
#   Phase 3 will upgrade this with full frequency analysis.

from engine.caesar import caesar_decode

# ─────────────────────────────────────────────
# A hand-picked list of very common English words.
# Short, high-frequency words catch the most signal.
# You can expand this list freely — more words = better scoring.
# ─────────────────────────────────────────────
COMMON_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all",
    "can", "had", "her", "was", "one", "our", "out", "day",
    "get", "has", "him", "his", "how", "man", "new", "now",
    "old", "see", "two", "way", "who", "its", "let", "put",
    "say", "she", "too", "use", "that", "with", "have", "this",
    "will", "your", "from", "they", "know", "want", "been",
    "good", "much", "some", "time", "very", "when", "come",
    "here", "just", "like", "long", "make", "many", "more",
    "only", "over", "such", "take", "than", "them", "then",
    "well", "were", "what", "would", "there", "their", "about",
    "which", "could", "other", "after", "first", "never", "these",
    "think", "where", "being", "every", "great", "might", "shall",
    "still", "those", "under", "while", "should", "people", "before",
    "little", "world", "without", "always", "because", "between",
    "message", "hello", "please", "secret", "cipher", "decode"
}


def score_text(text):
    """
    Scores a decoded string by counting how many common English words it contains.

    Args:
        text (str): A decoded candidate string.

    Returns:
        int: The number of common words found. Higher = better.

    How it works:
        1. Lowercase the whole text (so "The" matches "the")
        2. Split into individual words
        3. Strip punctuation from each word's edges (handles "word." or ",word")
        4. Count how many of those words appear in our COMMON_WORDS set
    """
    lowered = text.lower()

    # Split on whitespace to get individual tokens
    tokens = lowered.split()

    count = 0
    for token in tokens:
        # Strip common punctuation from the start and end of each word.
        # e.g. "hello." → "hello", ",world" → "world"
        word = token.strip(".,!?;:\"'()-")

        if word in COMMON_WORDS:
            count += 1

    return count


def brute_force_caesar(ciphertext):
    """
    Tries all 26 possible Caesar shifts and scores each decoded result.

    Args:
        ciphertext (str): The encrypted message (shift unknown).

    Returns:
        list of dicts, sorted best score first. Each dict contains:
            {
                "shift": int,         # The shift tried (1–25, plus 0 = no shift)
                "decoded": str,       # The decoded text at this shift
                "score": int          # How many common words were found
            }

    Note:
        Shift 0 means no change — included so the table is complete (all 26).
        The highest-scoring result is the most likely original message.
    """
    results = []

    for shift in range(26):  # 0 through 25
        decoded = caesar_decode(ciphertext, shift)
        score   = score_text(decoded)

        results.append({
            "shift":   shift,
            "decoded": decoded,
            "score":   score
        })

    # Sort so the best candidates appear first.
    # key=lambda r: r["score"] picks the score field for comparison.
    # reverse=True puts highest score at index 0.
    results.sort(key=lambda r: r["score"], reverse=True)

    return results
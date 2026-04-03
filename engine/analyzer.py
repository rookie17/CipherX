from engine.caesar import caesar_decode

# English letter frequency as percentages, A–Z
ENGLISH_FREQ = {
    'a': 8.2,  'b': 1.5,  'c': 2.8,  'd': 4.3,  'e': 12.7,
    'f': 2.2,  'g': 2.0,  'h': 6.1,  'i': 7.0,  'j': 0.15,
    'k': 0.77, 'l': 4.0,  'm': 2.4,  'n': 6.7,  'o': 7.5,
    'p': 1.9,  'q': 0.10, 'r': 6.0,  's': 6.3,  't': 9.1,
    'u': 2.8,  'v': 0.98, 'w': 2.4,  'x': 0.15, 'y': 2.0,
    'z': 0.07
}

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


def letter_frequency(text):
    """
    Returns each letter's percentage share of all letters in the text.
    Non-letter characters are ignored entirely.
    e.g. "Aab" → {'a': 66.67, 'b': 33.33, ...rest 0.0}
    """
    lowered = text.lower()
    counts = {ch: 0 for ch in ENGLISH_FREQ}

    for ch in lowered:
        if ch in counts:
            counts[ch] += 1

    total = sum(counts.values())

    if total == 0:
        return {ch: 0.0 for ch in counts}

    return {ch: (count / total) * 100 for ch, count in counts.items()}


def frequency_score(text):
    """
    Compares the text's letter frequencies against standard English.
    Uses chi-squared distance — lower distance = closer to English.
    We negate it so a higher return value always means a better score.

    Chi-squared formula per letter:
        (observed_freq - expected_freq)^2 / expected_freq
    Summed across all 26 letters gives the total distance.
    """
    observed = letter_frequency(text)
    chi_squared = 0.0

    for ch in ENGLISH_FREQ:
        expected = ENGLISH_FREQ[ch]
        obs      = observed[ch]
        chi_squared += ((obs - expected) ** 2) / expected

    return -chi_squared  # negate: less distance = better = higher score


def word_score(text):
    count = 0
    for token in text.lower().split():
        word = token.strip(".,!?;:\"'()-")
        if word in COMMON_WORDS:
            count += 1
    return count


def combined_score(text):
    """
    Blends frequency analysis with word matching.

    Weights:
        Frequency score  — good for short or garbled text with few real words
        Word score x 10  — heavily rewarded when real words appear
                           (multiplied so it can outweigh frequency noise)

    Both signals together are more reliable than either alone.
    """
    freq  = frequency_score(text)
    words = word_score(text) * 10
    return freq + words


def brute_force_caesar(ciphertext):
    results = []

    for shift in range(26):
        decoded = caesar_decode(ciphertext, shift)
        score   = combined_score(decoded)

        results.append({
            "shift":   shift,
            "decoded": decoded,
            "score":   round(score, 2)
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results
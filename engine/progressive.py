# engine/progressive.py
# Progressive shift cipher: each character is shifted by a different amount.
# shift_at_position = (start_shift + position * step) % 26
# 'position' only increments on letters — punctuation and spaces are skipped.

from engine.analyzer import combined_score


def progressive_encode(text, start_shift, step):
    """
    Encodes text with a progressive shift.

    Args:
        text        (str): Plain text to encrypt.
        start_shift (int): Shift applied to the first letter.
        step        (int): How much the shift increases per letter.

    Returns:
        str: Encrypted text.
    """
    result   = []
    position = 0  # Tracks letter count only — not total character count

    for char in text:
        if char.isalpha():
            base  = ord('A') if char.isupper() else ord('a')
            shift = (start_shift + position * step) % 26
            encoded_char = chr((ord(char) - base + shift) % 26 + base)
            result.append(encoded_char)
            position += 1  # Only advance on letters
        else:
            result.append(char)  # Spaces and punctuation pass through unchanged

    return ''.join(result)


def progressive_decode(text, start_shift, step):
    """
    Decodes a progressively-shifted text when start and step are known.
    Decoding = encoding with the complementary shift (26 - shift).
    """
    result   = []
    position = 0

    for char in text:
        if char.isalpha():
            base  = ord('A') if char.isupper() else ord('a')
            shift = (start_shift + position * step) % 26
            decoded_char = chr((ord(char) - base - shift) % 26 + base)
            result.append(decoded_char)
            position += 1
        else:
            result.append(char)

    return ''.join(result)


def brute_force_progressive(ciphertext, keywords=None, top_n=10):
    """
    Tries all 26 × 26 = 676 combinations of start_shift and step.
    Returns the top_n results ranked by combined_score.

    Args:
        ciphertext (str)         : The encrypted text.
        keywords   (list of str) : Optional hints, passed to combined_score.
        top_n      (int)         : How many results to return (default 10).

    Returns:
        list of dicts sorted best → worst:
        { "start": int, "step": int, "decoded": str, "score": float }

    Note:
        step=0 is equivalent to a standard Caesar cipher (shift never changes).
        start=0, step=0 means no transformation at all.
        676 candidates is fast — pure Python handles it in milliseconds.
    """
    results = []

    for start in range(26):
        for step in range(26):
            decoded = progressive_decode(ciphertext, start, step)
            score   = combined_score(decoded, keywords or [])

            results.append({
                "start":   start,
                "step":    step,
                "decoded": decoded,
                "score":   round(score, 2)
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_n]  # Only return the top N — 676 rows would be unreadable
# engine/noise_handler.py
# Strips noise from ciphertext before passing it to any decoder.
# "Noise" = non-alphabetic characters injected to obscure the real message.

import re
from engine.analyzer import combined_score, brute_force_caesar
from engine.progressive import brute_force_progressive


# ── Noise profiles ──────────────────────────────────────────────────────────
# Each profile defines a pattern of noise that can be stripped.
# Profiles are tried in order — first match wins.

NOISE_PROFILES = {
    "every_nth": "Noise character inserted at every N-th position",
    "non_alpha": "Strip all non-alphabetic characters (spaces kept)",
    "digits":    "Strip digits only — letters and punctuation kept",
    "symbols":   "Strip symbols only — letters, digits, spaces kept",
}


def strip_non_alpha(text, keep_spaces=True):
    """
    Removes all characters that aren't letters (and optionally spaces).
    The most aggressive and most common noise removal strategy.

    e.g. "Kh#oo!r Z3ru*og" → "Khoor Zruog"  (keep_spaces=True)
         "Kh#oo!r Z3ru*og" → "KhoorZruog"   (keep_spaces=False)
    """
    if keep_spaces:
        return re.sub(r'[^a-zA-Z ]', '', text)
    return re.sub(r'[^a-zA-Z]', '', text)


def strip_digits(text):
    return re.sub(r'\d', '', text)


def strip_symbols(text):
    return re.sub(r'[^a-zA-Z0-9 ]', '', text)


def strip_every_nth(text, n, offset=0):
    """
    Removes every N-th character, treating only letters as the signal.
    Non-letters are passed through untouched.

    Args:
        text   (str): The noisy ciphertext.
        n      (int): Keep every N-th letter, discard the rest.
                      e.g. n=2 keeps positions 0,2,4,... (every other letter)
        offset (int): Starting position within each group of N.
                      Lets you pick which character in each group is the real one.

    How it works:
        We count only letters. Every time the letter count modulo n equals
        the offset, we keep that letter. All others (noise letters) are dropped.
        Spaces and punctuation always pass through unchanged.

    e.g. strip_every_nth("AxBxCx", n=2, offset=0) → "ABC"  (keep even positions)
         strip_every_nth("xAxBxC", n=2, offset=1) → "ABC"  (keep odd positions)
    """
    result       = []
    letter_count = 0

    for char in text:
        if char.isalpha():
            if letter_count % n == offset:
                result.append(char)
            letter_count += 1
        else:
            result.append(char)  # Non-letters always kept

    return ''.join(result)


def detect_noise_profile(text):
    """
    Analyses the text and returns a best-guess noise profile name.

    Heuristics used:
        - High digit ratio      → 'digits'
        - High symbol ratio     → 'symbols'  
        - Very low letter ratio → 'non_alpha' (mixed noise)
        - Otherwise             → 'non_alpha' as safe default

    Returns:
        str: One of the keys in NOISE_PROFILES.
    """
    if not text:
        return 'non_alpha'

    total   = len(text)
    letters = sum(1 for c in text if c.isalpha())
    digits  = sum(1 for c in text if c.isdigit())
    symbols = sum(1 for c in text if not c.isalnum() and not c.isspace())

    digit_ratio  = digits  / total
    symbol_ratio = symbols / total
    letter_ratio = letters / total

    if digit_ratio > 0.2 and symbol_ratio < 0.1:
        return 'digits'
    if symbol_ratio > 0.2 and digit_ratio < 0.1:
        return 'symbols'
    if letter_ratio < 0.6:
        return 'non_alpha'

    return 'non_alpha'  # Safe default


def apply_profile(text, profile, nth=2, offset=0):
    """
    Applies a named noise profile to a text string.

    Args:
        text    (str): Noisy ciphertext.
        profile (str): Profile name — key from NOISE_PROFILES.
        nth     (int): Used only for 'every_nth' profile.
        offset  (int): Used only for 'every_nth' profile.

    Returns:
        str: Cleaned text ready for decoding.
    """
    if profile == 'non_alpha':
        return strip_non_alpha(text)
    if profile == 'digits':
        return strip_digits(text)
    if profile == 'symbols':
        return strip_symbols(text)
    if profile == 'every_nth':
        return strip_every_nth(text, nth, offset)
    return text  # Unknown profile — return unchanged


def denoise_and_decode(text, keywords=None, nth=2):
    """
    Full noise-resilient decode pipeline:

        1. Auto-detect noise profile
        2. Apply all profiles (so the user sees each result)
        3. Run Caesar brute force on each cleaned version
        4. Pick the best result across all profiles

    Args:
        text     (str)       : Raw noisy ciphertext.
        keywords (list[str]) : Optional hints for scoring.
        nth      (int)       : N value for every_nth profile.

    Returns:
        dict with:
            "best"     → the single best (profile, shift, decoded, score)
            "by_profile" → list of best result per profile, for display
    """
    keywords  = keywords or []
    by_profile = []

    profiles_to_try = [
        ('non_alpha', apply_profile(text, 'non_alpha')),
        ('digits',    apply_profile(text, 'digits')),
        ('symbols',   apply_profile(text, 'symbols')),
    ]

    # Also try every_nth for offsets 0 and 1 with the supplied nth value
    for offset in range(nth):
        cleaned = strip_every_nth(text, nth, offset)
        profiles_to_try.append((f'every_{nth}th_offset_{offset}', cleaned))

    for profile_name, cleaned in profiles_to_try:
        if not cleaned.strip():
            continue

        candidates = brute_force_caesar(cleaned, keywords)

        if not candidates:
            continue

        best_candidate = candidates[0]  # Already sorted — top score is first

        by_profile.append({
            "profile": profile_name,
            "cleaned": cleaned,
            "shift":   best_candidate["shift"],
            "decoded": best_candidate["decoded"],
            "score":   best_candidate["score"]
        })

    if not by_profile:
        return {"best": None, "by_profile": []}

    # Best overall = highest score across all profiles
    by_profile.sort(key=lambda r: r["score"], reverse=True)
    best = by_profile[0]

    return {"best": best, "by_profile": by_profile}
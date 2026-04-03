# engine/segment.py
# Segment-based shift cipher: the text is divided into fixed-size chunks.
# Each chunk is encrypted with its own independent Caesar shift.
# The shifts are supplied as a list: [shift_seg1, shift_seg2, ...]
# If the text has more segments than shifts, the shift list wraps around (cycles).

from engine.caesar import caesar_encode, caesar_decode
from engine.analyzer import combined_score
import itertools


def _split_into_segments(text, seg_size):
    """
    Splits text into chunks of seg_size characters.
    The final chunk may be shorter if the text doesn't divide evenly.

    e.g. split("HelloWorld", 4) → ["Hell", "oWor", "ld"]
    """
    return [text[i:i + seg_size] for i in range(0, len(text), seg_size)]


def segment_encode(text, seg_size, shifts):
    """
    Encodes text by applying a different Caesar shift to each segment.

    Args:
        text     (str)       : Plain text to encrypt.
        seg_size (int)       : Number of characters per segment.
        shifts   (list[int]) : Shift for each segment. Cycles if text has more
                               segments than shifts provided.

    Returns:
        str: Encrypted text.
    """
    segments      = _split_into_segments(text, seg_size)
    shift_cycle   = itertools.cycle(shifts)  # Wraps the shift list if needed
    encoded_parts = []

    for segment in segments:
        shift = next(shift_cycle)
        encoded_parts.append(caesar_encode(segment, shift))

    return ''.join(encoded_parts)


def segment_decode(text, seg_size, shifts):
    """
    Decodes a segment-encrypted text when seg_size and shifts are known.

    Args:
        text     (str)       : Encrypted text.
        seg_size (int)       : The segment size used during encoding.
        shifts   (list[int]) : The shifts used during encoding.

    Returns:
        str: Decrypted text.
    """
    segments      = _split_into_segments(text, seg_size)
    shift_cycle   = itertools.cycle(shifts)
    decoded_parts = []

    for segment in segments:
        shift = next(shift_cycle)
        decoded_parts.append(caesar_decode(segment, shift))

    return ''.join(decoded_parts)


def brute_force_segment(ciphertext, seg_size, num_shifts, keywords=None, top_n=10):
    """
    Brute-forces a segment cipher when the shifts are unknown.

    Strategy:
        We try every possible combination of shifts across all segments.
        Candidate space = 26 ^ num_shifts (grows fast, keep num_shifts small).

        num_shifts=2 →    676 candidates  (fast)
        num_shifts=3 → 17,576 candidates  (still fine)
        num_shifts=4 → 456,976 candidates (slow — warn the user)

    Args:
        ciphertext  (str)       : Encrypted text.
        seg_size    (int)       : Characters per segment.
        num_shifts  (int)       : How many distinct shifts to try (= number of
                                  unique segments assumed in the message).
        keywords    (list[str]) : Optional hints passed to combined_score.
        top_n       (int)       : How many results to return.

    Returns:
        list of dicts sorted best → worst:
        { "shifts": list[int], "decoded": str, "score": float }
    """
    results  = []
    keywords = keywords or []

    # itertools.product generates every combination of shifts.
    # e.g. product(range(26), repeat=2) gives (0,0),(0,1),...,(25,25)
    for shift_combo in itertools.product(range(26), repeat=num_shifts):
        decoded = segment_decode(ciphertext, seg_size, list(shift_combo))
        score   = combined_score(decoded, keywords)

        results.append({
            "shifts":  list(shift_combo),
            "decoded": decoded,
            "score":   round(score, 2)
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_n]


def estimate_brute_force_size(num_shifts):
    """
    Returns the total number of combinations for a given num_shifts.
    Used to warn the user before running a large brute force.
    """
    return 26 ** num_shifts
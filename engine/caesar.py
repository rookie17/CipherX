# engine/caesar.py
# Handles all Standard Caesar cipher operations.
# Caesar cipher: shift every letter forward (encode) or backward (decode) by a fixed number.
# Non-letter characters (spaces, punctuation, numbers) are left untouched.

def caesar_encode(text, shift):
    """
    Encodes plain text using a Caesar cipher.

    Args:
        text  (str): The message to encrypt.
        shift (int): How many positions to shift each letter (1–25).

    Returns:
        str: The encrypted message.

    Example:
        caesar_encode("Hello", 3) → "Khoor"
    """

    # Clamp the shift to stay within 1–25 range.
    # Using modulo 26 handles any number safely (e.g. shift=27 becomes shift=1).
    shift = shift % 26

    result = []  # We'll collect each processed character here

    for char in text:
        if char.isalpha():  # Only shift letters, skip everything else
            # Determine the base: 'A' for uppercase, 'a' for lowercase
            base = ord('A') if char.isupper() else ord('a')

            # How it works:
            # 1. ord(char) - base  → converts letter to a 0–25 number (A=0, B=1 ... Z=25)
            # 2. + shift           → apply the shift
            # 3. % 26              → wrap around if we go past Z (e.g. Z+1 = A)
            # 4. + base            → convert back to an ASCII code
            # 5. chr(...)          → convert ASCII code back to a character
            shifted = chr((ord(char) - base + shift) % 26 + base)
            result.append(shifted)
        else:
            result.append(char)  # Leave spaces, numbers, punctuation as-is

    return ''.join(result)  # Combine the list back into a single string


def caesar_decode(text, shift):
    """
    Decodes a Caesar-encrypted message when the shift is already known.

    Args:
        text  (str): The encrypted message.
        shift (int): The shift that was used to encode it.

    Returns:
        str: The decrypted (original) message.

    Strategy:
        Decoding is just encoding in reverse — shift backward by the same amount.
        Shifting forward by (26 - shift) gives the same result as shifting backward.

    Example:
        caesar_decode("Khoor", 3) → "Hello"
    """

    # Decoding = encoding with the opposite shift.
    # Instead of going backward, we go forward by (26 - shift),
    # which lands on the same letter. Clean and reuses our encode logic.
    return caesar_encode(text, 26 - shift)
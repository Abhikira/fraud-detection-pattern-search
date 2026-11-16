"""
Custom implementation of KMP and Rabin-Karp string matching algorithms.

Features:
- Case-insensitive matching.
- Finds all occurrences of a pattern.
- Handles overlapping matches.
- Returns zero-based starting indices.
"""

def build_lps(pattern):
    """
    Build the Longest Prefix Suffix (LPS) array for KMP.

    LPS[i] stores the length of the longest proper prefix
    that is also a suffix of pattern[0:i+1].
    """
    m = len(pattern)
    lps = [0] * m

    length = 0
    i = 1

    while i < m:
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1

        elif length > 0:
            length = lps[length - 1]

        else:
            lps[i] = 0
            i += 1

    return lps


def kmp_search(text, pattern):
    """
    Search for all occurrences of pattern using KMP.

    Returns a list of zero-based starting indices.
    Time Complexity: O(n + m)
    Space Complexity: O(m)
    """
    text = text.casefold()
    pattern = pattern.casefold()

    n = len(text)
    m = len(pattern)

    if m == 0 or m > n:
        return []

    lps = build_lps(pattern)

    matches = []
    i = 0
    j = 0

    while i < n:

        if text[i] == pattern[j]:
            i += 1
            j += 1

            if j == m:
                matches.append(i - j)

                # Continue searching for overlapping matches.
                j = lps[j - 1]

        elif j > 0:
            j = lps[j - 1]

        else:
            i += 1

    return matches


def rabin_karp_search(text, pattern, base=256, mod=1_000_000_007):
    """
    Search for all occurrences of pattern using Rabin-Karp.

    Uses a rolling hash to efficiently compare substrings.
    Verifies characters whenever hashes match to avoid
    false matches caused by hash collisions.

    Returns a list of zero-based starting indices.
    Average Time Complexity: O(n + m)
    Worst-case Time Complexity: O(n * m)
    Space Complexity: O(1), excluding the output list.
    """
    text = text.casefold()
    pattern = pattern.casefold()

    n = len(text)
    m = len(pattern)

    if m == 0 or m > n:
        return []

    # Calculate the highest power of base needed
    # to remove the leftmost character from the hash.
    high = pow(base, m - 1, mod)

    pattern_hash = 0
    window_hash = 0

    # Calculate initial pattern and text-window hashes.
    for i in range(m):
        pattern_hash = (pattern_hash * base + ord(pattern[i])) % mod
        window_hash = (window_hash * base + ord(text[i])) % mod

    matches = []

    # Slide the window across the text.
    for i in range(n - m + 1):

        # Compare hashes first.
        if pattern_hash == window_hash:

            # Verify actual characters to prevent collision errors.
            if text[i:i + m] == pattern:
                matches.append(i)

        # Calculate hash for the next window.
        if i < n - m:

            window_hash = (
                (window_hash - ord(text[i]) * high) * base
                + ord(text[i + m])
            ) % mod

    return matches


# Dictionary for selecting the required algorithm.
ALGORITHMS = {
    "KMP": kmp_search,
    "RABIN_KARP": rabin_karp_search
}
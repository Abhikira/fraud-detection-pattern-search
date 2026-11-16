"""Custom KMP and Rabin-Karp string matching (case-insensitive)."""


def build_lps(pattern):
    """Longest Prefix-Suffix array used by KMP."""
    lps = [0] * len(pattern)
    length, i = 0, 1
    while i < len(pattern):
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1
        elif length:
            length = lps[length - 1]
        else:
            lps[i] = 0
            i += 1
    return lps


def kmp_search(text, pattern):
    """Return all start indices of pattern in text."""
    text, pattern = text.lower(), pattern.lower()
    n, m = len(text), len(pattern)
    if m == 0 or m > n:
        return []
    lps, res, i, j = build_lps(pattern), [], 0, 0
    while i < n:
        if text[i] == pattern[j]:
            i += 1
            j += 1
            if j == m:
                res.append(i - m)
                j = lps[j - 1]
        elif j:
            j = lps[j - 1]
        else:
            i += 1
    return res


def rabin_karp_search(text, pattern, base=256, mod=1_000_000_007):
    """Rolling-hash search; each hash hit is verified character by character."""
    text, pattern = text.lower(), pattern.lower()
    n, m = len(text), len(pattern)
    if m == 0 or m > n:
        return []
    high = pow(base, m - 1, mod)
    p_hash = t_hash = 0
    for k in range(m):
        p_hash = (p_hash * base + ord(pattern[k])) % mod
        t_hash = (t_hash * base + ord(text[k])) % mod
    res = []
    for i in range(n - m + 1):
        if p_hash == t_hash and text[i:i + m] == pattern:  # verify (collision guard)
            res.append(i)
        if i < n - m:
            t_hash = ((t_hash - ord(text[i]) * high) * base + ord(text[i + m])) % mod
    return res


ALGORITHMS = {"KMP": kmp_search, "RABIN_KARP": rabin_karp_search}

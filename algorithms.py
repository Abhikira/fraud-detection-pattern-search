
def build_lps(pattern):
   
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

                
                j = lps[j - 1]

        elif j > 0:
            j = lps[j - 1]

        else:
            i += 1

    return matches


def rabin_karp_search(text, pattern, base=256, mod=1_000_000_007):
    
    text = text.casefold()
    pattern = pattern.casefold()

    n = len(text)
    m = len(pattern)

    if m == 0 or m > n:
        return []

   
    high = pow(base, m - 1, mod)

    pattern_hash = 0
    window_hash = 0


    for i in range(m):
        pattern_hash = (pattern_hash * base + ord(pattern[i])) % mod
        window_hash = (window_hash * base + ord(text[i])) % mod

    matches = []

   
    for i in range(n - m + 1):

        
        if pattern_hash == window_hash:

            
            if text[i:i + m] == pattern:
                matches.append(i)

    
        if i < n - m:

            window_hash = (
                (window_hash - ord(text[i]) * high) * base
                + ord(text[i + m])
            ) % mod

    return matches



ALGORITHMS = {
    "KMP": kmp_search,
    "RABIN_KARP": rabin_karp_search
}
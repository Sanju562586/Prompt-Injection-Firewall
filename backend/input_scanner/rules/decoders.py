import base64
import re
import urllib.parse
from typing import List, Tuple

# Common zero-width and invisible unicode characters
ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u00A0\u2028\u2029]")

# Leetspeak translation table
LEET_DICT = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i'
}

# Regex to detect potential Base64 strings (minimum length 16 to reduce false positives on small words)
BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Regex to detect hex-encoded bytes like \x69\x67 or 0x69
HEX_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]{2}[\s,]*){4,}")


class ObfuscationDecoder:
    """
    Decodes and normalizes obfuscated text representations (Base64, Hex, URL, Leetspeak,
    Zero-width smuggling) to uncover hidden prompt injection payloads.
    """

    @classmethod
    def strip_zero_width(cls, text: str) -> str:
        """Removes invisible unicode characters used for token smuggling."""
        return ZERO_WIDTH_CHARS.sub("", text)

    @classmethod
    def decode_url(cls, text: str) -> str:
        """Decodes URL-encoded strings (%20, %27, etc.)."""
        try:
            return urllib.parse.unquote(text)
        except Exception:
            return text

    @classmethod
    def decode_hex(cls, text: str) -> List[Tuple[str, str]]:
        """
        Finds hex byte patterns and decodes them into readable ascii text.
        Returns a list of (raw_hex, decoded_text) pairs.
        """
        results: List[Tuple[str, str]] = []
        matches = HEX_PATTERN.findall(text)
        for match in matches:
            try:
                cleaned = match.replace("\\x", "").replace("0x", "").replace(" ", "").replace(",", "")
                decoded = bytes.fromhex(cleaned).decode("utf-8", errors="ignore")
                if len(decoded.strip()) >= 4:
                    results.append((match, decoded))
            except Exception:
                continue
        return results

    @classmethod
    def decode_base64(cls, text: str) -> List[Tuple[str, str]]:
        """
        Detects Base64 blobs within the text, decodes them, and returns (raw_b64, decoded_text).
        Only keeps decoded text that produces printable ASCII/UTF-8 words.
        """
        results: List[Tuple[str, str]] = []
        matches = BASE64_PATTERN.findall(text)
        for match in set(matches):
            try:
                # Add padding if required
                missing_padding = len(match) % 4
                padded = match + ("=" * (4 - missing_padding) if missing_padding else "")
                decoded_bytes = base64.b64decode(padded)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                
                # Verify that decoded text is printable and substantial
                if len(decoded_str.strip()) >= 6 and all(31 < ord(c) < 127 or c in "\r\n\t" for c in decoded_str):
                    results.append((match, decoded_str))
            except Exception:
                continue
        return results

    @classmethod
    def normalize_leetspeak(cls, text: str) -> str:
        """Translates basic leetspeak substitutions back to standard English letters."""
        chars = [LEET_DICT.get(c, c) for c in text.lower()]
        return "".join(chars)

    @classmethod
    def collapse_spaced_letters(cls, text: str) -> str:
        """
        Detects token smuggling via spaced/hyphenated letters.
        Example: 'i - g - n - o - r - e' or 'i g n o r e' -> 'ignore'.
        """
        # Matches single letters separated by space or hyphens (3 or more consecutive)
        pattern = re.compile(r"(?:\b[a-zA-Z][\s\-_]){3,}[a-zA-Z]\b")
        def replacer(match):
            cleaned = re.sub(r"[\s\-_]", "", match.group(0))
            return cleaned
        return pattern.sub(replacer, text)

    @classmethod
    def generate_candidate_variants(cls, text: str) -> List[Tuple[str, str]]:
        """
        Generates all decoded and normalized candidate variations of the input text
        with their transformation label.
        Returns list of (variant_label, transformed_text).
        """
        variants: List[Tuple[str, str]] = [("raw", text)]

        # 1. Clean zero-width chars
        cleaned = cls.strip_zero_width(text)
        if cleaned != text:
            variants.append(("zero_width_stripped", cleaned))

        # 2. URL decode
        urldecoded = cls.decode_url(cleaned)
        if urldecoded != cleaned:
            variants.append(("url_decoded", urldecoded))

        # 3. Spaced letters normalization
        collapsed = cls.collapse_spaced_letters(cleaned)
        if collapsed != cleaned:
            variants.append(("spaced_letters_collapsed", collapsed))

        # 4. Leetspeak normalization
        leet_norm = cls.normalize_leetspeak(cleaned)
        if leet_norm != cleaned.lower():
            variants.append(("leetspeak_normalized", leet_norm))

        # 5. Base64 decodings embedded as candidates
        b64_matches = cls.decode_base64(text)
        for raw, decoded in b64_matches:
            variants.append((f"base64_decoded:{raw[:12]}...", decoded))

        # 6. Hex decodings embedded as candidates
        hex_matches = cls.decode_hex(text)
        for raw, decoded in hex_matches:
            variants.append((f"hex_decoded:{raw[:12]}...", decoded))

        return variants

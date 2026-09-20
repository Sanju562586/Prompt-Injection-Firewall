import re
from typing import List
from ..schemas import InjectedSpan, PoisoningType

# Detects HTML/Markdown comments containing instructions or prompt language
COMMENT_INJECTION_PATTERN = re.compile(
    r"<!--\s*(?:ai|system|assistant|instruction|prompt|secret|override|ignore)[^>]*?-->",
    re.IGNORECASE | re.DOTALL
)

# Detects hidden styling tricks (display:none, visibility:hidden, font-size:0, white-on-white)
HIDDEN_HTML_STYLE_PATTERN = re.compile(
    r"<[^>]+\bstyle=[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^\"']*[\"'][^>]*>(.*?)<\/[^>]+>",
    re.IGNORECASE | re.DOTALL
)

# Detects spans with high density of invisible/zero-width chars
ZERO_WIDTH_SPAN_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF]{3,}")


class StructuralDetector:
    """
    Detects structural and visual evasion techniques within retrieved documents,
    such as hidden comments, invisible HTML text, and zero-width payload smuggling.
    """

    @classmethod
    def scan(cls, text: str) -> List[InjectedSpan]:
        spans: List[InjectedSpan] = []

        # 1. Inspect HTML/Markdown Comments
        for match in COMMENT_INJECTION_PATTERN.finditer(text):
            spans.append(
                InjectedSpan(
                    start_char=match.start(),
                    end_char=match.end(),
                    detected_text=match.group(0),
                    poisoning_type=PoisoningType.HIDDEN_PAYLOAD,
                    confidence=0.92,
                    rule_name="Hidden Markdown/HTML Comment Directive"
                )
            )

        # 2. Inspect Hidden Style Tags
        for match in HIDDEN_HTML_STYLE_PATTERN.finditer(text):
            spans.append(
                InjectedSpan(
                    start_char=match.start(),
                    end_char=match.end(),
                    detected_text=match.group(0),
                    poisoning_type=PoisoningType.HIDDEN_PAYLOAD,
                    confidence=0.88,
                    rule_name="CSS-Hidden Text Tag"
                )
            )

        # 3. Inspect Zero-width clusters
        for match in ZERO_WIDTH_SPAN_PATTERN.finditer(text):
            spans.append(
                InjectedSpan(
                    start_char=match.start(),
                    end_char=match.end(),
                    detected_text="<zero-width-cluster>",
                    poisoning_type=PoisoningType.HIDDEN_PAYLOAD,
                    confidence=0.90,
                    rule_name="Zero-Width Character Smuggling"
                )
            )

        return spans

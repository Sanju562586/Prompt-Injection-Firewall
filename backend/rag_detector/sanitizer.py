import re
from typing import List, Tuple, Optional
from .schemas import InjectedSpan


class DocumentSanitizer:
    """
    Surgically excises malicious injection spans and trojan AI directives from
    retrieved documents, preserving benign knowledge and business facts for the LLM context.
    """

    @classmethod
    def sanitize(cls, text: str, spans: List[InjectedSpan]) -> Tuple[str, bool]:
        """
        Removes malicious spans from document text.
        Returns:
            - sanitized_text: Document text with malicious blocks excised
            - is_salvageable: True if sufficient clean legitimate text remains
        """
        if not spans or not text:
            return text, True

        # Sort spans in ascending order of start_char
        sorted_spans = sorted(spans, key=lambda s: (s.start_char, s.end_char))

        # Merge overlapping or contiguous spans, extending to line boundaries if part of a directive block
        merged_intervals: List[Tuple[int, int]] = []
        for span in sorted_spans:
            start = span.start_char
            end = span.end_char

            # Expand bounds to full paragraph/line boundary if it's a block directive
            line_start = text.rfind("\n", 0, start)
            if line_start == -1:
                line_start = 0
            else:
                line_start += 1

            line_end = text.find("\n", end)
            if line_end == -1:
                line_end = len(text)

            # If the snippet starts with an AI banner, expand downwards to cover subsequent commands
            block_start = line_start
            block_end = line_end

            if not merged_intervals:
                merged_intervals.append((block_start, block_end))
            else:
                prev_start, prev_end = merged_intervals[-1]
                if block_start <= prev_end + 2:  # Contiguous/adjacent lines
                    merged_intervals[-1] = (prev_start, max(prev_end, block_end))
                else:
                    merged_intervals.append((block_start, block_end))

        # Reconstruct sanitized text by omitting merged malicious intervals
        sanitized_parts = []
        cursor = 0
        for start, end in merged_intervals:
            if start > cursor:
                sanitized_parts.append(text[cursor:start])
            cursor = max(cursor, end)

        if cursor < len(text):
            sanitized_parts.append(text[cursor:])

        cleaned = "".join(sanitized_parts)

        # Normalize remaining whitespace
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()

        # A document is salvageable if it still retains substantive benign content
        is_salvageable = len(cleaned) >= 20 and any(c.isalnum() for c in cleaned)

        return cleaned, is_salvageable

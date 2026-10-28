# Full implementation: github.com/mastering-agentic-security/ch11
import unicodedata, re

# Visually-confusable code points that NFKC does NOT fold. Keep this table
# small and sourced from Unicode TR39 confusables; do not guess mappings.
CONFUSABLES = {
    0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c',  # Cyrillic
    0x03BF: 'o', 0x03B1: 'a',                                        # Greek
    0x1D00: 'a', 0x1D07: 'e', 0x1D0F: 'o',                           # Phonetic extensions
    0x0585: 'o', 0x0581: 'g',                                        # Armenian
}
# Fullwidth (U+FF01..FF5E) is handled by NFKC, so it is not listed here.

# Zero-width and variation-selector ranges. The variation-selector supplement
# (U+E0100..U+E01EF) is above U+FFFF, so it needs the eight-digit \U escape;
# the four-digit \u form parses as U+E010 followed by literal characters.
ZERO_WIDTH = re.compile(
    r'[\u200B-\u200D\u2060\uFEFF\u180E\uFE00-\uFE0F\U000E0100-\U000E01EF]+')

def canonical_form(text: str) -> str:
    text = unicodedata.normalize('NFKC', text)  # fold width, ligatures, compat forms
    text = ZERO_WIDTH.sub('', text)             # strip zero-width AFTER NFKC
    return ''.join(CONFUSABLES.get(ord(ch), ch) for ch in text)

def normalize_output(output: str) -> str:
    return canonical_form(output)

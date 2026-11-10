"""Control-split token masking: no-match fast path keeps outputs identical.

Regression cases ported from atchisonbrent/hermes-agent#6; the property test
compares against a verbatim copy of the pre-fast-path implementation.
All secrets here are synthetic.
"""
import random
import re
import string
from unittest.mock import patch

from agent import redact


def _oracle_mask_control_split_tokens(text, mask_fn):
    """Verbatim pre-change implementation (oracle)."""
    R = redact
    stripped = R._CONTROL_CHARS_RE.sub("", text)
    if stripped == text:
        return text
    orig_idx = [i for i, c in enumerate(text) if not R._CONTROL_CHARS_RE.match(c)]
    out, matches = list(text), []
    for m in R._PREFIX_RE.finditer(stripped):
        start_orig = orig_idx[m.start(1)]
        end_orig = orig_idx[m.end(1) - 1] + 1
        span = text[start_orig:end_orig]
        if ("\n" in span or "\r" in span) and R._PREFIX_RE.search(span):
            continue
        if (all(c in R._TOKEN_BODY_CHARS or R._CONTROL_CHARS_RE.match(c) for c in span)
                and (end_orig >= len(text) or text[end_orig] != "=")):
            matches.append((start_orig, end_orig, mask_fn(m.group(1))))
    for start_orig, end_orig, replacement in reversed(matches):
        out[start_orig:end_orig] = list(replacement)
    return "".join(out)


def _mask(tok):
    return f"<{len(tok)}:{tok[:3]}>"


def _valid_control_split_token(body="a1"):
    token = "ghp_" + body * 18
    assert redact._PREFIX_RE.fullmatch(token) is not None
    return token[:6] + "\x1b" + token[6:]


def test_no_prefix_match_skips_per_character_scan():
    text = "descriptive prefix sk-short " + "\x1b"
    assert redact._PREFIX_RE.search(redact._CONTROL_CHARS_RE.sub("", text)) is None
    with patch.object(redact, "_CONTROL_CHARS_RE", wraps=redact._CONTROL_CHARS_RE) as ctl:
        assert redact._mask_control_split_tokens(text, lambda _: "<m>") == text
        ctl.match.assert_not_called()


def test_multiple_control_split_tokens_preserve_order_and_prose():
    first, second = _valid_control_split_token("a1"), _valid_control_split_token("b2")
    calls = []

    def mask(tok):
        calls.append(tok)
        return f"<masked-{len(calls)}>"

    text = f"before {first} between {second} after"
    assert redact._mask_control_split_tokens(text, mask) == "before <masked-1> between <masked-2> after"
    assert calls == [first.replace("\x1b", ""), second.replace("\x1b", "")]


def test_rejected_first_match_does_not_drop_later_token():
    first, second = _valid_control_split_token("a1"), _valid_control_split_token("b2")
    calls = []

    def mask(tok):
        calls.append(tok)
        return "<masked>"

    text = f"before {first}=value between {second} after"
    assert redact._mask_control_split_tokens(text, mask) == f"before {first}=value between <masked> after"
    assert calls == [second.replace("\x1b", "")]
    calls.clear()
    only_rejected = f"before {first}=value after"
    assert redact._mask_control_split_tokens(only_rejected, mask) == only_rejected
    assert calls == []


def test_newlines_and_repeated_records_match_oracle():
    tok = _valid_control_split_token("c3")
    cases = [
        "ghp_" + "a1" * 18 + "\nbutton",
        "key ghp_abc\n123def456ghi789jkl0 end",
        "line1\nline2\r\nno tokens\x1b here\n",
        "\n".join([f"rec {i} {tok}" for i in range(50)]),
        "",
        "\x1b",
    ]
    for text in cases:
        assert redact._mask_control_split_tokens(text, _mask) == _oracle_mask_control_split_tokens(text, _mask)


_CONTROLS = ["\x1b", "\x00", "\x07", "\t", "\n", "\r", "\x7f", "\u200b", "\u200d",
             "\u2028", "\u202e", "\u2060", "\ufeff"]


def _synthetic_secrets(rng):
    """One synthetic token per _PREFIX_PATTERNS entry with a derivable literal prefix."""
    out = []
    for pat in redact._PREFIX_PATTERNS:
        lit = re.match(r"(?:[A-Za-z0-9_\-]|\\[.\-])+", pat)
        if not lit:
            continue
        prefix = lit.group(0).replace("\\.", ".").replace("\\-", "-")
        for body in ("".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40)),
                     "1-" + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(40)),
                     "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(16))):
            if redact._PREFIX_RE.search(prefix + body):
                out.append(prefix + body)
                break
    return out


def test_randomized_control_insertion_matches_oracle():
    rng = random.Random(0xA1)
    secrets = _synthetic_secrets(rng)
    assert len(secrets) >= 40  # covers essentially every prefix format
    fillers = ["", " ", "x", "KEY=", "=", "-", "_", ".", "word ", "\n", "prose text "]
    iterations = 0
    for _ in range(4000):
        parts = []
        for _ in range(rng.randint(1, 4)):
            s = list(rng.choice(secrets))
            if rng.random() < 0.3:
                s = s[: rng.randint(1, len(s))]  # truncated / non-matching
            for _ in range(rng.randint(0, 3)):
                s.insert(rng.randint(0, len(s)), rng.choice(_CONTROLS))
            parts.append(rng.choice(fillers) + "".join(s) + rng.choice(fillers))
        text = "".join(parts)
        assert redact._mask_control_split_tokens(text, _mask) == \
            _oracle_mask_control_split_tokens(text, _mask), repr(text)
        iterations += 1
    assert iterations == 4000

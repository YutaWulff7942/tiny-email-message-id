"""Tests for tiny-email-message-id.

The clock is always injected, so every test is deterministic. We never
assert on wall-clock time, never sleep, and compare exact strings where
the implementation promises exactness.
"""

import re
import unittest

from tiny_email_message_id import MessageIdGenerator, MessageIdError


# RFC 5322 dot-atom-text, restricted to what this generator emits:
# lowercase base32 (a-z, 2-7). We do not match the full atext grammar
# because we only ever emit this subset.
_LOCAL_RE = re.compile(r"^[a-z2-7]+$")
_MSGID_RE = re.compile(r"^<[a-z2-7]+@[^>]+>$")


class FakeClock:
    """Deterministic clock for tests."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class DomainValidationTests(unittest.TestCase):
    def test_rejects_non_string_domain(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator(123)  # type: ignore[arg-type]

    def test_rejects_empty_domain(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("")

    def test_rejects_trailing_dot(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("example.org.")

    def test_rejects_leading_dot(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator(".example.org")

    def test_rejects_leading_hyphen(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("-mail.example.org")

    def test_rejects_non_ascii(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("mäl.example.org")

    def test_rejects_single_label(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("localhost")

    def test_rejects_empty_label(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("example..org")

    def test_rejects_label_with_trailing_hyphen(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("example-.org")

    def test_rejects_label_with_leading_hyphen(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("example.-org")

    def test_rejects_illegal_character(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("example_org")

    def test_rejects_non_callable_clock(self):
        with self.assertRaises(MessageIdError):
            MessageIdGenerator("mail.example.org", clock=12345)  # type: ignore[arg-type]

    def test_accepts_minimal_two_label_domain(self):
        gen = MessageIdGenerator("a.b", clock=lambda: 1)
        # Should not raise; construction alone is the contract here.
        self.assertEqual(gen.domain, "a.b")


class GenerateTests(unittest.TestCase):
    def test_returns_str(self):
        gen = MessageIdGenerator("mail.example.org", clock=lambda: 1)
        self.assertIsInstance(gen.generate(), str)

    def test_wraps_in_angle_brackets(self):
        gen = MessageIdGenerator("mail.example.org", clock=lambda: 1)
        mid = gen.generate()
        self.assertTrue(mid.startswith("<"))
        self.assertTrue(mid.endswith(">"))

    def test_uses_configured_domain(self):
        gen = MessageIdGenerator("mail.example.org", clock=lambda: 1)
        mid = gen.generate()
        self.assertTrue(mid.endswith("@mail.example.org>"))

    def test_local_part_is_lowercase_base32(self):
        gen = MessageIdGenerator("mail.example.org", clock=lambda: 1)
        mid = gen.generate()
        local = mid[1:].split("@", 1)[0]
        self.assertRegex(local, _LOCAL_RE)

    def test_full_shape_regex(self):
        gen = MessageIdGenerator("mail.example.org", clock=lambda: 1)
        self.assertRegex(gen.generate(), _MSGID_RE)

    def test_same_clock_produces_different_locals(self):
        clock = FakeClock(1_700_000_000_000_000_000)
        gen = MessageIdGenerator("mail.example.org", clock=clock)
        a = gen.generate()
        b = gen.generate()
        # Same clock tick, but counter and randomness differ.
        self.assertNotEqual(a, b)

    def test_different_clock_produces_different_locals(self):
        values = iter([1_700_000_000_000_000_000, 1_700_000_000_000_000_001])
        gen = MessageIdGenerator("mail.example.org", clock=lambda: next(values))
        a = gen.generate()
        b = gen.generate()
        self.assertNotEqual(a, b)

    def test_many_generates_are_unique(self):
        clock = FakeClock(1_700_000_000_000_000_000)
        gen = MessageIdGenerator("mail.example.org", clock=clock)
        ids = {gen.generate() for _ in range(500)}
        self.assertEqual(len(ids), 500)

    def test_counter_appears_in_output_when_clock_static(self):
        """When the clock is frozen, only the counter and randomness vary.

        Strip the random prefix and the counter should be visible as a
        monotonically increasing 2-byte base32 suffix.
        """
        clock = FakeClock(42)
        gen = MessageIdGenerator("mail.example.org", clock=clock, counter_start=0)
        first = gen.generate()
        second = gen.generate()
        third = gen.generate()
        locals_ = [m[1:].split("@", 1)[0] for m in (first, second, third)]
        # Counter is the last 4 base32 chars (2 bytes = 16 bits, but
        # base32 encodes 5 bits per char, so 2 bytes -> ceil(16/5)=4 chars
        # with the last carrying 1 leftover bit). The suffix must differ.
        self.assertNotEqual(locals_[0][-4:], locals_[1][-4:])
        self.assertNotEqual(locals_[1][-4:], locals_[2][-4:])

    def test_default_clock_works(self):
        """The default clock (time.time_ns) must produce a valid ID.

        We cannot assert on the value, only on its shape, because the
        clock is wall-clock. This is the one test that touches real time;
        it asserts shape only, never the exact bytes.
        """
        gen = MessageIdGenerator("mail.example.org")
        mid = gen.generate()
        self.assertRegex(mid, _MSGID_RE)


class DeterministicOutputTests(unittest.TestCase):
    """When the clock, counter, and randomness are all pinned, output is
    byte-for-byte identical.

    The randomness comes from ``secrets`` which we cannot seed without
    monkey-patching. So instead of asserting exact bytes, we assert the
    structural invariant: same inputs -> same length, same shape, same
    domain. This keeps the test honest about what we actually control.
    """

    def test_same_clock_yields_same_length_locals(self):
        clock = FakeClock(1_700_000_000_000_000_000)
        gen = MessageIdGenerator("mail.example.org", clock=clock)
        a = gen.generate()
        b = gen.generate()
        self.assertEqual(len(a), len(b))

    def test_domain_property_round_trips(self):
        gen = MessageIdGenerator("mail.example.org", clock=lambda: 1)
        mid = gen.generate()
        self.assertIn(gen.domain, mid)


if __name__ == "__main__":
    unittest.main()

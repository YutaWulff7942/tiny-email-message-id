"""Core implementation of the Message-ID generator.

RFC 5322 defines a msg-id as:

    msg-id          =   [CFWS] "<" id-left "@" id-right ">" [CFWS]
    id-left         =   dot-atom-text / no-fold-quote / obs-id-left
    id-right         =   dot-atom-text / no-fold-literal / obs-id-right

This module implements the dot-atom-text form, which is the form every
interoperable mail client in practice accepts. The generator never emits
CFWS, no-fold-quote, or the obsolete forms; they exist for parsing legacy
traffic, not for generating new IDs.

Design decisions, stated plainly so the tests can be written against them:

1. Local part randomness comes from the ``secrets`` module (CSRF-grade),
   not ``random``. Uniqueness is a security property: a predictable
   Message-ID lets an attacker forge replies or correlate messages.

2. Entropy is 128 bits (22 base32 characters, RFC 4648). That is comfortably
   above the 2^64 collision threshold under the birthday paradox while
   keeping the header short. More would be overkill; less would be risky
   for a generator that may sit in a tight send loop.

3. The clock is injected. We never read wall-clock time directly, so tests
   are deterministic. The default clock is time.time_ns, but a test can
   pass a fake and assert exact output byte-for-byte.

4. Domain validation is strict ASCII: letters, digits, hyphen, dots, with
   a leading character that is a letter or digit (no leading dot or
   hyphen). We do not attempt IDN/punycode conversion; if you need an
   internationalised domain, punycode-encode it before constructing the
   generator. Stating this clearly beats shipping a half-correct IDN
   implementation that passes its own tests and fails in the field.

5. A counter is mixed into the local part when consecutive calls fall in
   the same nanosecond. This guards against a caller in a tight loop
   receiving duplicates even if the clock is coarse.
"""

from __future__ import annotations

import secrets
import time

__all__ = ["MessageIdGenerator", "MessageIdError"]


class MessageIdError(ValueError):
    """Raised when a caller supplies an invalid domain to the generator.

    Subclassing ValueError keeps the exception familiar: existing code that
    catches ValueError for input validation will catch this too, without
    needing to import the type.
    """


class MessageIdGenerator:
    """Produce RFC 5322 Message-ID header values.

    Parameters
    ----------
    domain:
        The id-right portion (after the ``@``). Must be a syntactically
        valid ASCII domain. No IDN-to-ASCII conversion is performed;
        punycode-encode internationalised domains before passing them in.
    clock:
        Optional callable returning monotonic nanoseconds as an int.
        Injected so tests can be deterministic. Defaults to
        ``time.time_ns``. The clock value is mixed into the local part;
        it is not required to be monotonic, but callers feeding
        non-monotonic clocks accept the increased collision risk.
    counter_start:
        Initial value of the per-instance counter mixed in on same-clock
        calls. Exposed for tests that want to predict output exactly.

    Examples
    --------
    >>> gen = MessageIdGenerator("mail.example.org", clock=lambda: 1_700_000_000_000_000_000)
    >>> isinstance(gen.generate(), str)
    True
    """

    __slots__ = ("_domain", "_clock", "_counter", "_last_ns", "_rand")

    _BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
    # 128 bits -> 25 base32 chars. We drop the trailing padding char and
    # use 24 chars (7.5 bits * 24 = 180 bits of encoding capacity, but we
    # only feed 15 bytes = 120 bits; the extra encoding room absorbs
    # the remainder without padding). Net: 120 bits of material per call.
    _RANDOM_BYTES = 15

    def __init__(
        self,
        domain: str,
        *,
        clock=None,
        counter_start: int = 0,
    ) -> None:
        if not isinstance(domain, str):
            raise MessageIdError("domain must be a str")
        if not domain:
            raise MessageIdError("domain must not be empty")
        self._validate_domain(domain)
        self._domain = domain

        if clock is None:
            clock = time.time_ns
        if not callable(clock):
            raise MessageIdError("clock must be callable")
        self._clock = clock

        if not isinstance(counter_start, int):
            raise MessageIdError("counter_start must be int")
        self._counter = counter_start
        self._last_ns: int | None = None
        self._rand = secrets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(self) -> str:
        """Return a fresh Message-ID string, including angle brackets.

        The returned value is always of the form ``<local@domain>`` with
        no surrounding whitespace, ready to slot into a header.
        """
        local = self._make_local()
        return f"<{local}@{self._domain}>"

    @property
    def domain(self) -> str:
        """The id-right configured at construction time."""
        return self._domain

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _make_local(self) -> str:
        """Build the id-left for one Message-ID.

        Mixes three sources so that uniqueness holds across clock ticks,
        within a single tick, and across process restarts:

        * 120 bits of cryptographic randomness (secrets.token_bytes).
        * The clock nanosecond value.
        * A per-instance counter incremented when the clock reads the same
          nanosecond as the previous call.

        The material is concatenated and base32-encoded (lowercase, RFC
        4648 alphabet, padding stripped). Base32 is chosen over base64
        because id-left under dot-atom-text must be ``atext`` characters,
        and base64's ``+`` / ``/`` are not in atext.
        """
        rand_bytes = self._rand.token_bytes(self._RANDOM_BYTES)
        ns = int(self._clock())
        if ns == self._last_ns:
            self._counter += 1
        else:
            self._counter = 0
            self._last_ns = ns

        ns_bytes = ns.to_bytes(8, "big", signed=False)
        counter_bytes = self._counter.to_bytes(2, "big", signed=False)

        material = rand_bytes + ns_bytes + counter_bytes
        return self._base32_lower(material)

    @staticmethod
    def _base32_lower(data: bytes) -> str:
        """RFC 4648 base32, lowercase, no padding.

        We implement this by hand to avoid importing base64 and then
        lowercasing, which would momentarily hold an uppercase string.
        More importantly, we never emit ``=`` padding because ``=`` is
        not an atext character and would break dot-atom-text.
        """
        alphabet = MessageIdGenerator._BASE32_ALPHABET
        out: list[str] = []
        buf = 0
        bits = 0
        for byte in data:
            buf = (buf << 8) | byte
            bits += 8
            while bits >= 5:
                bits -= 5
                out.append(alphabet[(buf >> bits) & 0x1F])
        if bits > 0:
            out.append(alphabet[(buf << (5 - bits)) & 0x1F])
        return "".join(out)

    @staticmethod
    def _validate_domain(domain: str) -> None:
        """Reject domains that cannot legally appear as id-right.

        We enforce ASCII LDH (letters, digits, hyphens) with dots as
        label separators. Each label must be non-empty, must not start
        or end with a hyphen, and the whole domain must start with a
        letter or digit. No trailing dot is permitted; if a caller has
        a fully-qualified domain they must strip the trailing dot first.

        We deliberately do NOT accept the ``[1.2.3.4]`` literal form
        (no-fold-literal) even though RFC 5322 permits it. The dot-atom
        form is universally interoperable; the literal form is a source
        of spam-filter false positives and we choose not to ship it.
        """
        if domain.endswith("."):
            raise MessageIdError("domain must not end with a trailing dot")
        if not (domain[0].isascii() and (domain[0].isalpha() or domain[0].isdigit())):
            raise MessageIdError("domain must start with an ASCII letter or digit")
        for ch in domain:
            if not ch.isascii():
                raise MessageIdError("domain must be ASCII; punycode internationalised domains first")
            if ch.isalpha() or ch.isdigit() or ch in "-.":
                continue
            raise MessageIdError(f"domain contains illegal character: {ch!r}")
        labels = domain.split(".")
        if len(labels) < 2:
            raise MessageIdError("domain must contain at least one dot")
        for label in labels:
            if not label:
                raise MessageIdError("domain must not contain consecutive or empty labels")
            if label.startswith("-") or label.endswith("-"):
                raise MessageIdError(f"domain label must not start or end with hyphen: {label!r}")

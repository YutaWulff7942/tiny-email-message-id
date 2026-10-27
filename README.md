# tiny-email-message-id

Generates RFC 5322 compliant Message-ID header values with cryptographic randomness and an injectable clock.

## Usage

```python
from tiny_email_message_id import MessageIdGenerator

gen = MessageIdGenerator("mail.example.org")
msg_id = gen.generate()
# -> "<a1b2c3d4...@mail.example.org>"
```

For deterministic tests, pass a clock:

```python
gen = MessageIdGenerator("mail.example.org", clock=lambda: 1_700_000_000_000_000_000)
assert gen.generate().startswith("<")
```

## Why this exists

Message-ID uniqueness is a security property: a predictable ID lets an attacker forge replies or correlate mail. This library generates IDs using 120 bits of `secrets`-grade randomness mixed with a clock value and a per-instance counter, so uniqueness holds across clock ticks, within a single tick, and across process restarts.

The trade-off: the local part is opaque base32. It is not human-meaningful. If you want sequence numbers or hostnames in the local part, this library is the wrong tool — those leak information and harm deliverability.

## Edge cases

- **Internationalised domains are not supported.** Punycode-encode the domain before constructing the generator. Shipping a half-correct IDN implementation is worse than not shipping one.
- **No trailing dot.** A domain ending in `.` is rejected; strip it first if you have a fully-qualified name.
- **No IP literals.** The `[1.2.3.4]` form permitted by RFC 5322 is intentionally not emitted; dot-atom domains are universally interoperable and IP literals trigger spam filters.
- **The clock is injected.** The default is `time.time_ns`; tests pass a fake. Output is never asserted on wall-clock time.

## API

- `MessageIdGenerator(domain, *, clock=None, counter_start=0)` — constructor. Raises `MessageIdError` (a `ValueError` subclass) on an invalid domain.
- `generate() -> str` — returns a `"<local@domain>"` string.
- `domain` — read-only property returning the configured id-right.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.


## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.


## License

MIT.

"""tiny-email-message-id

Generates RFC 5322 compliant Message-ID headers.

The public surface is intentionally tiny: a single class, MessageIdGenerator,
which produces globally unique, syntactically valid Message-ID strings
suitable for use as the value of a Message-ID or In-Reply-To header.
"""

from tiny_email_message_id.core import MessageIdGenerator, MessageIdError

__all__ = ["MessageIdGenerator", "MessageIdError"]

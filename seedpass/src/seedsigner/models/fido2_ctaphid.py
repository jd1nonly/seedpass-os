"""
CTAPHID -- the USB HID transport underneath CTAP2.

A host talks to a FIDO authenticator in 64-byte reports. Messages larger than
one report are split into an initialisation packet and a run of continuation
packets, and this reassembles them.

It is a small protocol, but it is the first thing a hostile host touches, so
every field it supplies is treated as an attack:

* **Declared payload length** is bounded at MAX_MESSAGE_BYTES before a buffer is
  allocated. The field is 16 bits, so a host can claim 65535 bytes; the spec's
  own ceiling is 7609.
* **Sequence numbers** must arrive in order, starting at zero. Out-of-order or
  repeated continuation packets abort the transaction rather than being
  reordered, which would let a host rewrite a buffer it had already filled.
* **Channel IDs** are checked on every packet. A second channel interleaving
  packets into someone else's transaction gets BUSY, not a share of the buffer.
* **Unfinished transactions expire.** A host that sends an init packet claiming
  7609 bytes and then goes quiet would otherwise pin that memory indefinitely.

Deliberately not implemented: CTAPHID_WINK (a physical notification with no
security purpose), CTAPHID_LOCK (channel locking, optional and a denial-of
service lever), and the U2F/CTAP1 MSG command. A CTAP1 path would be a second,
older code path reachable by any host, and the value of supporting legacy U2F
does not justify the extra surface.
"""
import os
import struct
import time


class CtapHidError(Exception):
    pass


PACKET_BYTES = 64
INIT_PAYLOAD_BYTES = PACKET_BYTES - 7        # 4 channel + 1 cmd + 2 length
CONT_PAYLOAD_BYTES = PACKET_BYTES - 5        # 4 channel + 1 sequence

# The spec's maximum message size. Also the largest buffer a host can make this
# device hold.
MAX_MESSAGE_BYTES = 7609

MAX_SEQUENCE = 0x7F

BROADCAST_CHANNEL = 0xFFFFFFFF
RESERVED_CHANNEL = 0x00000000

# A transaction left unfinished for this long is discarded.
TRANSACTION_TIMEOUT_SECONDS = 5.0

# Commands. The high bit marks an initialisation packet.
CMD_PING = 0x81
CMD_MSG = 0x83          # CTAP1/U2F -- answered with a "not supported" error
CMD_INIT = 0x86
CMD_CBOR = 0x90
CMD_CANCEL = 0x91
CMD_KEEPALIVE = 0xBB
CMD_ERROR = 0xBF

# Error codes
ERR_INVALID_CMD = 0x01
ERR_INVALID_PAR = 0x02
ERR_INVALID_LEN = 0x03
ERR_INVALID_SEQ = 0x04
ERR_MSG_TIMEOUT = 0x05
ERR_CHANNEL_BUSY = 0x06
ERR_INVALID_CHANNEL = 0x0B
ERR_OTHER = 0x7F

# Keepalive status
STATUS_PROCESSING = 0x01
STATUS_UPNEEDED = 0x02

CTAPHID_PROTOCOL_VERSION = 2

# Capability flags reported by INIT.
CAPABILITY_WINK = 0x01
CAPABILITY_CBOR = 0x04
CAPABILITY_NMSG = 0x08   # "this device does NOT speak CTAP1/U2F"

# CBOR yes, U2F no. Advertising NMSG matters: without it a host is entitled to
# try CTAPHID_MSG and will sit waiting for a reply that never comes. Saying so
# up front also keeps the legacy path from being probed at all.
CAPABILITIES = CAPABILITY_CBOR | CAPABILITY_NMSG


def build_packets(channel: int, command: int, payload: bytes) -> list:
    """Split a message into 64-byte reports, padded with zeros."""
    if len(payload) > MAX_MESSAGE_BYTES:
        raise CtapHidError("Message exceeds the maximum size")

    packets = []

    head = struct.pack(">IBH", channel, command, len(payload))
    chunk = payload[:INIT_PAYLOAD_BYTES]
    packets.append((head + chunk).ljust(PACKET_BYTES, b"\x00"))

    offset = INIT_PAYLOAD_BYTES
    sequence = 0
    while offset < len(payload):
        if sequence > MAX_SEQUENCE:
            raise CtapHidError("Too many continuation packets")
        head = struct.pack(">IB", channel, sequence)
        chunk = payload[offset:offset + CONT_PAYLOAD_BYTES]
        packets.append((head + chunk).ljust(PACKET_BYTES, b"\x00"))
        offset += CONT_PAYLOAD_BYTES
        sequence += 1

    return packets


def build_error(channel: int, code: int) -> list:
    return build_packets(channel, CMD_ERROR, bytes([code]))


def build_keepalive(channel: int, status: int) -> bytes:
    return build_packets(channel, CMD_KEEPALIVE, bytes([status]))[0]


class Transaction:
    """One message being reassembled."""

    def __init__(self, channel: int, command: int, expected: int, first_chunk: bytes):
        self.channel = channel
        self.command = command
        self.expected = expected
        self.buffer = bytearray(first_chunk[:expected])
        self.next_sequence = 0
        self.started = time.monotonic()

    @property
    def complete(self) -> bool:
        return len(self.buffer) >= self.expected

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.started > TRANSACTION_TIMEOUT_SECONDS


class CtapHid:
    """
    Reassembles CTAPHID packets into complete messages.

    `handle_packet` takes one 64-byte report and returns either None (more
    expected) or a `(channel, command, payload)` tuple ready to be acted on.
    Protocol-level replies -- INIT, errors -- are returned through
    `pending_responses` so the caller can write them straight back.
    """

    def __init__(self):
        self.transaction = None
        self.pending_responses = []
        self._next_channel = 1

    def _allocate_channel(self) -> int:
        """
        Hand out a fresh channel ID.

        Sequential rather than random on purpose: channel IDs are not a security
        boundary -- any host process can see and use any of them -- and a
        predictable counter avoids consuming entropy for no benefit.
        """
        channel = self._next_channel
        self._next_channel += 1
        if self._next_channel >= BROADCAST_CHANNEL:
            self._next_channel = 1
        return channel

    def _fail(self, channel: int, code: int):
        self.transaction = None
        self.pending_responses.extend(build_error(channel, code))
        return None

    def handle_packet(self, packet: bytes):
        if len(packet) != PACKET_BYTES:
            # The USB stack delivers fixed-size reports; anything else means the
            # layer below is broken, not that a host was creative.
            raise CtapHidError("Packet is not 64 bytes")

        channel = struct.unpack(">I", packet[0:4])[0]

        if channel == RESERVED_CHANNEL:
            return self._fail(channel, ERR_INVALID_CHANNEL)

        # Drop a stalled transaction before considering the new packet, so a
        # host that abandoned one cannot block the device.
        if self.transaction is not None and self.transaction.expired:
            self.transaction = None

        is_init = bool(packet[4] & 0x80)

        if is_init:
            command = packet[4]
            length = struct.unpack(">H", packet[5:7])[0]

            if command == CMD_INIT:
                return self._handle_init(channel, packet)

            if channel == BROADCAST_CHANNEL:
                # Only INIT is meaningful on the broadcast channel.
                return self._fail(channel, ERR_INVALID_CHANNEL)

            if length > MAX_MESSAGE_BYTES:
                return self._fail(channel, ERR_INVALID_LEN)

            if command == CMD_MSG:
                # CTAP1/U2F. Declined rather than implemented: it is a second,
                # older command path any host could reach, and NMSG above tells
                # well-behaved hosts not to ask.
                return self._fail(channel, ERR_INVALID_CMD)

            if command == CMD_CANCEL:
                self.transaction = None
                return (channel, CMD_CANCEL, b"")

            if self.transaction is not None and self.transaction.channel != channel:
                # Another channel is mid-transaction. Do not disturb it.
                self.pending_responses.extend(build_error(channel, ERR_CHANNEL_BUSY))
                return None

            self.transaction = Transaction(channel, command, length, packet[7:])

            if self.transaction.complete:
                return self._finish()
            return None

        # ---- continuation packet
        sequence = packet[4]

        if self.transaction is None:
            # Nothing is being assembled; a stray continuation is a spoofing
            # attempt or a confused host either way.
            return self._fail(channel, ERR_INVALID_SEQ)

        if self.transaction.channel != channel:
            self.pending_responses.extend(build_error(channel, ERR_CHANNEL_BUSY))
            return None

        if sequence != self.transaction.next_sequence:
            # Out of order. Refusing rather than reordering: accepting a repeat
            # would let a host overwrite part of a buffer it had already sent.
            return self._fail(channel, ERR_INVALID_SEQ)

        self.transaction.next_sequence += 1
        remaining = self.transaction.expected - len(self.transaction.buffer)
        self.transaction.buffer.extend(packet[5:5 + min(remaining, CONT_PAYLOAD_BYTES)])

        if self.transaction.complete:
            return self._finish()
        return None

    def _handle_init(self, channel: int, packet: bytes):
        """
        INIT: allocate a channel and report capabilities.

        The host's 8-byte nonce is echoed back so it can tell its own response
        apart from another process's.
        """
        length = struct.unpack(">H", packet[5:7])[0]
        if length != 8:
            return self._fail(channel, ERR_INVALID_LEN)

        nonce = packet[7:15]

        if channel == BROADCAST_CHANNEL:
            allocated = self._allocate_channel()
        else:
            # INIT on an established channel is the documented way to abort a
            # transaction and resynchronise.
            allocated = channel
            if self.transaction is not None and self.transaction.channel == channel:
                self.transaction = None

        response = (
            nonce
            + struct.pack(">I", allocated)
            + bytes([
                CTAPHID_PROTOCOL_VERSION,
                1, 0, 0,          # device version major/minor/build
                CAPABILITIES,
            ])
        )
        self.pending_responses.extend(build_packets(channel, CMD_INIT, response))
        return None

    def _finish(self):
        transaction = self.transaction
        self.transaction = None
        return (transaction.channel, transaction.command, bytes(transaction.buffer))

    def take_responses(self) -> list:
        """Collect and clear queued protocol-level replies."""
        responses = self.pending_responses
        self.pending_responses = []
        return responses

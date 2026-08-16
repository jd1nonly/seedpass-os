"""
The USB HID endpoint for CTAP2.

Once the gadget is configured, the kernel presents `/dev/hidg0`: reads return
64-byte reports the host sent, writes deliver 64-byte reports back. That is the
whole interface. Everything above it -- framing, CBOR, credentials -- is already
built and tested; this is the part that touches the device.

Reads are non-blocking with a short timeout rather than blocking outright. A
blocking read would leave the armed screen unable to notice its own back button,
so the device could only be freed by unplugging it. Polling keeps the UI alive
between packets, at the cost of a loop that wakes a few times a second.

The transport is deliberately behind a small interface with a fake
implementation, because none of this can be exercised without a Pi Zero and a
host. The fake lets the view logic, the confirmation prompt and the refusal
paths be tested for real; only the file I/O is left unverified.
"""
import os
import select


HID_DEVICE = "/dev/hidg0"
PACKET_BYTES = 64

# Long enough to avoid spinning, short enough that a button press feels
# immediate.
POLL_TIMEOUT_SECONDS = 0.1


class TransportError(Exception):
    pass


class HidTransport:
    """Reads and writes 64-byte reports on the USB HID endpoint."""

    def __init__(self, path: str = HID_DEVICE):
        self.path = path
        self._fd = None

    @property
    def is_open(self) -> bool:
        return self._fd is not None

    def open(self) -> None:
        if self._fd is not None:
            return
        try:
            # Unbuffered: HID reports are packet-oriented, and buffering would
            # merge or split them.
            self._fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK)
        except OSError as e:
            raise TransportError(
                f"Cannot open {self.path}: {e}. Is the USB gadget configured "
                f"and a host connected?"
            )

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    def read_packet(self):
        """One 64-byte report, or None if nothing arrived before the timeout."""
        if self._fd is None:
            raise TransportError("Transport is not open")

        readable, _, _ = select.select([self._fd], [], [], POLL_TIMEOUT_SECONDS)
        if not readable:
            return None

        try:
            data = os.read(self._fd, PACKET_BYTES)
        except BlockingIOError:
            return None
        except OSError as e:
            raise TransportError(f"Read failed: {e}")

        if not data:
            return None

        # The kernel delivers whole reports. A short read means the host
        # disconnected mid-transfer, and padding it would feed the framing layer
        # a packet that was never sent.
        if len(data) != PACKET_BYTES:
            raise TransportError(f"Short read: {len(data)} bytes")

        return data

    def write_packet(self, packet: bytes) -> None:
        if self._fd is None:
            raise TransportError("Transport is not open")
        if len(packet) != PACKET_BYTES:
            raise TransportError("Packet must be exactly 64 bytes")

        try:
            os.write(self._fd, packet)
        except OSError as e:
            raise TransportError(f"Write failed: {e}")

    def write_packets(self, packets) -> None:
        for packet in packets:
            self.write_packet(packet)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exception):
        self.close()


class FakeTransport:
    """
    A scripted transport for tests.

    `queue` holds packets the "host" will send; `sent` collects what the device
    wrote back. `read_packet` returns None once the queue is empty, which is how
    a real transport reports an idle link.
    """

    def __init__(self, queue=None):
        self.queue = list(queue or [])
        self.sent = []
        self.opened = False
        self.closed = False

    @property
    def is_open(self) -> bool:
        return self.opened and not self.closed

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def read_packet(self):
        if not self.queue:
            return None
        return self.queue.pop(0)

    def write_packet(self, packet: bytes) -> None:
        if len(packet) != PACKET_BYTES:
            raise TransportError("Packet must be exactly 64 bytes")
        self.sent.append(packet)

    def write_packets(self, packets) -> None:
        for packet in packets:
            self.write_packet(packet)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exception):
        self.close()

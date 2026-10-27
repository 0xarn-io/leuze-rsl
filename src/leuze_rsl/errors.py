"""Exception types raised by leuze_rsl.

Every exception raised by this package derives from :class:`RSL235Error`, so
``except RSL235Error`` catches all of them.  Where a builtin type is the
conventional one (``TimeoutError`` for a timeout, ``ValueError`` for bad
data) the package exception additionally derives from it, so idiomatic
``except TimeoutError`` / ``except ValueError`` keep working.
"""


class RSL235Error(Exception):
    """Base class for all leuze_rsl errors."""


class ScannerConnectionError(RSL235Error):
    """Establishing or keeping a connection / socket failed."""


class NotConnectedError(ScannerConnectionError):
    """An operation required an open connection but there is none."""


class ReceiverStoppedError(RSL235Error):
    """The receiver was stopped (or never started) while waiting for a scan."""


class CommandTimeoutError(RSL235Error):
    """The scanner did not answer a command within the timeout."""


class CommandError(RSL235Error):
    """The scanner answered a command with something unexpected."""


class ScanTimeoutError(RSL235Error, TimeoutError):
    """No scan arrived within the requested timeout.

    Also a ``TimeoutError`` for backwards compatibility.
    """


class ProtocolError(RSL235Error, ValueError):
    """Received data violates the wire protocol.

    Also a ``ValueError`` for backwards compatibility with earlier releases
    whose parsers raised ``ValueError``.
    """

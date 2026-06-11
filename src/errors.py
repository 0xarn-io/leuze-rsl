"""Exception types raised by pyrsl235."""


class RSL235Error(Exception):
    """Base class for all pyrsl235 errors."""


class ScannerConnectionError(RSL235Error):
    """Establishing or keeping the TCP connection to the scanner failed."""


class NotConnectedError(ScannerConnectionError):
    """An operation required an open connection but there is none."""


class CommandTimeoutError(RSL235Error):
    """The scanner did not answer a command within the timeout."""


class CommandError(RSL235Error):
    """The scanner answered a command with something unexpected."""


class ProtocolError(RSL235Error):
    """Received data violates the wire protocol."""

class RelayAxisError(Exception):
    """Expected, user-visible operational failure (never include credentials)."""


class ValidationError(RelayAxisError):
    pass


class ConflictError(RelayAxisError):
    pass


class ApplyError(RelayAxisError):
    pass


class SystemError(RelayAxisError):
    pass

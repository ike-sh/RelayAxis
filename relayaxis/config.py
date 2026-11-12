from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    """A relocatable filesystem layout; --root never changes the real host files."""

    root: Path = Path("/")

    @property
    def config(self):
        return self.root / "etc/relayaxis"

    @property
    def state(self):
        return self.root / "var/lib/relayaxis"

    @property
    def units(self):
        return self.root / "etc/systemd/system"

    @property
    def database(self):
        return self.state / "state.sqlite3"

    @property
    def backups(self):
        return self.state / "backups"

    def initialize(self):
        from .errors import ValidationError

        for path in (self.config, self.state, self.backups, self.state / "journals"):
            if path.is_symlink():
                raise ValidationError("RelayAxis 配置或状态目录不能是符号链接")
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)

import json
import os
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from .errors import ConflictError, ValidationError
from .models import now

SCHEMA_VERSION = 1


def canonical(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Store:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise ValidationError("数据库不能是符号链接")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise ValidationError("数据库来自更新版本，拒绝降级写入")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS objects (
                    kind TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
                    data TEXT NOT NULL, PRIMARY KEY(kind,id));
                CREATE TABLE IF NOT EXISTS history (
                    kind TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
                    data TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(kind,id,revision));
                CREATE TABLE IF NOT EXISTS runtime (key TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS changes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                    id TEXT NOT NULL, revision INTEGER NOT NULL, at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
                    subject TEXT NOT NULL, state TEXT NOT NULL, message TEXT NOT NULL);
            """)
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    def get(self, kind, object_id, db=None):
        if db is None:
            with self.connect() as conn:
                return self.get(kind, object_id, conn)
        row = db.execute(
            "SELECT data FROM objects WHERE kind=? AND id=?", (kind, object_id)
        ).fetchone()
        if row is None:
            raise ValidationError(f"未找到 {kind}: {object_id}")
        return json.loads(row[0])

    def list(self, kind, db=None):
        if db is None:
            with self.connect() as conn:
                return self.list(kind, conn)
        return [
            json.loads(r[0])
            for r in db.execute("SELECT data FROM objects WHERE kind=? ORDER BY id", (kind,))
        ]

    def put(self, kind, object_id, data, expected=None, db=None):
        if db is None:
            with self.transaction() as conn:
                return self.put(kind, object_id, data, expected, conn)
        row = db.execute(
            "SELECT revision FROM objects WHERE kind=? AND id=?", (kind, object_id)
        ).fetchone()
        revision = row[0] if row else 0
        if expected is not None and expected != revision:
            raise ConflictError(f"版本冲突: 预期 {expected}，当前 {revision}")
        historical = db.execute(
            "SELECT COALESCE(MAX(revision),0) FROM history WHERE kind=? AND id=?", (kind, object_id)
        ).fetchone()[0]
        next_revision = max(revision, historical) + 1
        result = dict(data, revision=next_revision)
        if kind == "rule":
            result["created_at"] = data.get("created_at") or now()
            result["updated_at"] = now()
        encoded = canonical(result)
        db.execute(
            "INSERT OR REPLACE INTO objects VALUES (?,?,?,?)",
            (kind, object_id, next_revision, encoded),
        )
        db.execute(
            "INSERT INTO history VALUES (?,?,?,?,?)",
            (kind, object_id, next_revision, encoded, now()),
        )
        db.execute(
            "INSERT INTO changes(kind,id,revision,at) VALUES (?,?,?,?)",
            (kind, object_id, next_revision, now()),
        )
        return result

    def remove(self, kind, object_id, db=None):
        if db is None:
            with self.transaction() as conn:
                return self.remove(kind, object_id, conn)
        data = self.get(kind, object_id, db)
        db.execute("DELETE FROM objects WHERE kind=? AND id=?", (kind, object_id))
        db.execute(
            "INSERT INTO changes(kind,id,revision,at) VALUES (?,?,?,?)",
            (kind, object_id, data["revision"] + 1, now()),
        )

    def history(self, kind, object_id):
        with self.connect() as db:
            return [
                json.loads(r[0])
                for r in db.execute(
                    "SELECT data FROM history WHERE kind=? AND id=? ORDER BY revision",
                    (kind, object_id),
                )
            ]

    def runtime(self, key, default=None, db=None):
        if db is None:
            with self.connect() as conn:
                return self.runtime(key, default, conn)
        row = db.execute("SELECT data FROM runtime WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_runtime(self, key, data, db=None):
        if db is None:
            with self.transaction() as conn:
                return self.set_runtime(key, data, conn)
        db.execute("INSERT OR REPLACE INTO runtime VALUES (?,?)", (key, canonical(data)))
        if key.startswith(("rule:", "sync:")) and isinstance(data, dict) and "state" in data:
            db.execute(
                "INSERT INTO events(at,subject,state,message) VALUES (?,?,?,?)",
                (now(), key, data["state"], str(data.get("error", ""))[:1024]),
            )

    def events(self, limit=100):
        if not 1 <= limit <= 1000:
            raise ValidationError("日志条数必须在 1–1000 之间")
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute("SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,))
            ]

    def sequence(self):
        with self.connect() as db:
            return db.execute("SELECT COALESCE(MAX(seq),0) FROM changes").fetchone()[0]

    def backup(self, destination):
        with self.connect() as source, closing(sqlite3.connect(destination)) as target:
            source.backup(target)
        os.chmod(destination, 0o600)

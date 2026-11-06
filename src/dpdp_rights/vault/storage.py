"""Vault storage backends: SQL (any SQLAlchemy URL), DynamoDB, Firestore."""
from __future__ import annotations

from typing import Protocol

from sqlalchemy import Boolean, Column, LargeBinary, MetaData, String, Table, create_engine, delete, select


class VaultStorage(Protocol):
    def put_key(self, principal_id: str, wrapped: bytes) -> None: ...
    def get_key(self, principal_id: str) -> bytes | None: ...
    def delete_key(self, principal_id: str) -> None: ...
    def put_value(self, token: str, principal_id: str, element_type: str, ciphertext: bytes, third_party: bool) -> None: ...
    def get_value(self, token: str) -> tuple[str, str, bytes] | None: ...
    def tokens_for(self, principal_id: str) -> list[str]: ...
    def delete_values(self, principal_id: str) -> int: ...
    def put_lookup(self, lookup_hash: str, principal_id: str) -> None: ...
    def get_lookup(self, lookup_hash: str) -> str | None: ...
    def delete_lookups(self, principal_id: str) -> int: ...


class SqlVaultStorage:
    def __init__(self, url: str):
        if url.startswith("sqlite:///"):
            from pathlib import Path

            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, future=True)
        md = MetaData()
        self.keys = Table(
            "vault_key", md,
            Column("principal_id", String(64), primary_key=True),
            Column("wrapped_dek", LargeBinary, nullable=False),
        )
        self.values = Table(
            "vault_value", md,
            Column("token", String(64), primary_key=True),
            Column("principal_id", String(64), index=True, nullable=False),
            Column("element_type", String(40), nullable=False),
            Column("ciphertext", LargeBinary, nullable=False),
            Column("third_party", Boolean, default=False),
        )
        self.lookups = Table(
            "vault_lookup", md,
            Column("lookup_hash", String(64), primary_key=True),
            Column("principal_id", String(64), index=True, nullable=False),
        )
        md.create_all(self.engine)

    def _upsert(self, table, key_col: str, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(delete(table).where(table.c[key_col] == row[key_col]))
            c.execute(table.insert().values(**row))

    def put_key(self, principal_id, wrapped):
        self._upsert(self.keys, "principal_id", {"principal_id": principal_id, "wrapped_dek": wrapped})

    def get_key(self, principal_id):
        with self.engine.connect() as c:
            r = c.execute(select(self.keys.c.wrapped_dek).where(self.keys.c.principal_id == principal_id)).first()
            return r[0] if r else None

    def delete_key(self, principal_id):
        with self.engine.begin() as c:
            c.execute(delete(self.keys).where(self.keys.c.principal_id == principal_id))

    def put_value(self, token, principal_id, element_type, ciphertext, third_party):
        self._upsert(self.values, "token", dict(token=token, principal_id=principal_id,
                                                element_type=element_type, ciphertext=ciphertext,
                                                third_party=third_party))

    def get_value(self, token):
        with self.engine.connect() as c:
            r = c.execute(select(self.values.c.principal_id, self.values.c.element_type,
                                 self.values.c.ciphertext).where(self.values.c.token == token)).first()
            return (r[0], r[1], r[2]) if r else None

    def tokens_for(self, principal_id):
        with self.engine.connect() as c:
            return [r[0] for r in c.execute(select(self.values.c.token).where(self.values.c.principal_id == principal_id))]

    def delete_values(self, principal_id):
        with self.engine.begin() as c:
            return c.execute(delete(self.values).where(self.values.c.principal_id == principal_id)).rowcount

    def put_lookup(self, lookup_hash, principal_id):
        self._upsert(self.lookups, "lookup_hash", {"lookup_hash": lookup_hash, "principal_id": principal_id})

    def get_lookup(self, lookup_hash):
        with self.engine.connect() as c:
            r = c.execute(select(self.lookups.c.principal_id).where(self.lookups.c.lookup_hash == lookup_hash)).first()
            return r[0] if r else None

    def delete_lookups(self, principal_id):
        with self.engine.begin() as c:
            return c.execute(delete(self.lookups).where(self.lookups.c.principal_id == principal_id)).rowcount


class DynamoDBVaultStorage:
    """Three tables: <prefix>_keys (pk principal_id), <prefix>_values (pk token, GSI principal_id-index),
    <prefix>_lookups (pk lookup_hash, GSI principal_id-index). See deploy/terraform/aws."""

    def __init__(self, prefix: str, region: str | None = None, resource=None):
        import boto3

        ddb = resource or boto3.resource("dynamodb", region_name=region)
        self.keys = ddb.Table(f"{prefix}_keys")
        self.values = ddb.Table(f"{prefix}_values")
        self.lookups = ddb.Table(f"{prefix}_lookups")

    @staticmethod
    def _query_all(table, principal_id: str, attr: str) -> list[str]:
        from boto3.dynamodb.conditions import Key

        out, kwargs = [], {"IndexName": "principal_id-index",
                           "KeyConditionExpression": Key("principal_id").eq(principal_id)}
        while True:
            r = table.query(**kwargs)
            out += [i[attr] for i in r.get("Items", [])]
            if "LastEvaluatedKey" not in r:
                return out
            kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def put_key(self, principal_id, wrapped):
        self.keys.put_item(Item={"principal_id": principal_id, "wrapped_dek": wrapped})

    def get_key(self, principal_id):
        i = self.keys.get_item(Key={"principal_id": principal_id}).get("Item")
        return bytes(i["wrapped_dek"].value if hasattr(i["wrapped_dek"], "value") else i["wrapped_dek"]) if i else None

    def delete_key(self, principal_id):
        self.keys.delete_item(Key={"principal_id": principal_id})

    def put_value(self, token, principal_id, element_type, ciphertext, third_party):
        self.values.put_item(Item={"token": token, "principal_id": principal_id, "element_type": element_type,
                                   "ciphertext": ciphertext, "third_party": third_party})

    def get_value(self, token):
        i = self.values.get_item(Key={"token": token}).get("Item")
        if not i:
            return None
        ct = i["ciphertext"]
        return i["principal_id"], i["element_type"], bytes(ct.value if hasattr(ct, "value") else ct)

    def tokens_for(self, principal_id):
        return self._query_all(self.values, principal_id, "token")

    def delete_values(self, principal_id):
        toks = self.tokens_for(principal_id)
        with self.values.batch_writer() as b:
            for t in toks:
                b.delete_item(Key={"token": t})
        return len(toks)

    def put_lookup(self, lookup_hash, principal_id):
        self.lookups.put_item(Item={"lookup_hash": lookup_hash, "principal_id": principal_id})

    def get_lookup(self, lookup_hash):
        i = self.lookups.get_item(Key={"lookup_hash": lookup_hash}).get("Item")
        return i["principal_id"] if i else None

    def delete_lookups(self, principal_id):
        hashes = self._query_all(self.lookups, principal_id, "lookup_hash")
        with self.lookups.batch_writer() as b:
            for h in hashes:
                b.delete_item(Key={"lookup_hash": h})
        return len(hashes)


class FirestoreVaultStorage:
    def __init__(self, prefix: str, project: str | None = None, client=None, database: str | None = None):
        if client is None:
            from google.cloud import firestore  # type: ignore

            kw = {"database": database} if database else {}
            client = firestore.Client(project=project, **kw)
        db = client
        self.keys = db.collection(f"{prefix}_keys")
        self.values = db.collection(f"{prefix}_values")
        self.lookups = db.collection(f"{prefix}_lookups")

    def put_key(self, principal_id, wrapped):
        self.keys.document(principal_id).set({"wrapped_dek": wrapped})

    def get_key(self, principal_id):
        d = self.keys.document(principal_id).get()
        return d.to_dict()["wrapped_dek"] if d.exists else None

    def delete_key(self, principal_id):
        self.keys.document(principal_id).delete()

    def put_value(self, token, principal_id, element_type, ciphertext, third_party):
        self.values.document(token.strip("<>")).set({"token": token, "principal_id": principal_id,
                                                      "element_type": element_type, "ciphertext": ciphertext,
                                                      "third_party": third_party})

    def get_value(self, token):
        d = self.values.document(token.strip("<>")).get()
        if not d.exists:
            return None
        v = d.to_dict()
        return v["principal_id"], v["element_type"], v["ciphertext"]

    def tokens_for(self, principal_id):
        return [d.to_dict()["token"] for d in self.values.where("principal_id", "==", principal_id).stream()]

    def delete_values(self, principal_id):
        n = 0
        for d in self.values.where("principal_id", "==", principal_id).stream():
            d.reference.delete()
            n += 1
        return n

    def put_lookup(self, lookup_hash, principal_id):
        self.lookups.document(lookup_hash).set({"principal_id": principal_id})

    def get_lookup(self, lookup_hash):
        d = self.lookups.document(lookup_hash).get()
        return d.to_dict()["principal_id"] if d.exists else None

    def delete_lookups(self, principal_id):
        n = 0
        for d in self.lookups.where("principal_id", "==", principal_id).stream():
            d.reference.delete()
            n += 1
        return n


def build_storage(cfg, default_sql_url: str) -> VaultStorage:
    if cfg.storage == "sql":
        return SqlVaultStorage(cfg.sql_url or default_sql_url)
    if cfg.storage == "dynamodb":
        return DynamoDBVaultStorage(cfg.dynamodb_table_prefix, cfg.region)
    if cfg.storage == "firestore":
        return FirestoreVaultStorage(cfg.firestore_collection_prefix, cfg.project, database=cfg.firestore_database)
    raise ValueError(f"Unknown vault storage {cfg.storage}")

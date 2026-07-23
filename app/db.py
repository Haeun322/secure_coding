"""SQLite 연결 관리.

모든 쿼리는 이 모듈이 돌려주는 connection 을 통해 파라미터 바인딩(?)으로만
실행한다. 문자열 포매팅으로 SQL 을 만드는 코드는 프로젝트 어디에도 두지 않는다.
이것이 SQL Injection 을 막는 1차 방어선이다.
"""
import os
import sqlite3

from flask import current_app, g


def get_db():
    """요청 컨텍스트당 하나의 연결을 재사용한다."""
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=10,
        )
        g.db.row_factory = sqlite3.Row          # 컬럼명을 키로 접근 가능
        g.db.execute("PRAGMA foreign_keys = ON")  # 외래키 제약 활성화(기본은 꺼짐)
        # WAL: 읽기와 쓰기가 서로를 막지 않게 해 동시성을 높인다.
        # busy_timeout: 잠금이 잡혀 있으면 즉시 실패하지 않고 잠시 대기한다.
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 5000")
        g.db.execute("PRAGMA synchronous = NORMAL")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_write_connection():
    """송금처럼 원자성이 중요한 작업 전용 연결.

    isolation_level=None(자동커밋)으로 열어 BEGIN IMMEDIATE ~ COMMIT 을 직접 제어한다.
    busy_timeout 을 줘서 동시 송금이 겹치면 오류 대신 잠시 대기하도록 한다.
    요청용 g.db 와 분리해 트랜잭션 경계를 명확히 한다.
    """
    conn = sqlite3.connect(
        current_app.config["DATABASE"],
        isolation_level=None,
        timeout=10,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    """스키마를 적용한다. 이미 있으면 IF NOT EXISTS 로 넘어간다."""
    db = get_db()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as fh:
        db.executescript(fh.read())
    _migrate(db)
    db.commit()


def _migrate(db):
    """기존 DB에 없는 컬럼을 안전하게 추가한다(데이터 보존).

    CREATE TABLE IF NOT EXISTS 는 기존 테이블의 컬럼을 바꾸지 못하므로,
    나중에 추가된 컬럼은 여기서 ALTER TABLE 로 채운다. 이미 있으면 건너뛴다.
    """
    product_cols = {row["name"] for row in db.execute("PRAGMA table_info(products)")}
    if "category" not in product_cols:
        db.execute("ALTER TABLE products ADD COLUMN category TEXT NOT NULL DEFAULT 'etc'")
    if "region" not in product_cols:
        db.execute("ALTER TABLE products ADD COLUMN region TEXT NOT NULL DEFAULT ''")
    # category 컬럼이 확실히 있는 지금 시점에 인덱스를 만든다.
    db.execute("CREATE INDEX IF NOT EXISTS idx_products_category ON products(category)")

    # 메시지에 product_id 추가(상품별 대화). 기존 메시지는 product_id NULL 로 남는다.
    message_cols = {row["name"] for row in db.execute("PRAGMA table_info(messages)")}
    if "product_id" not in message_cols:
        db.execute("ALTER TABLE messages ADD COLUMN product_id INTEGER")
    db.execute("CREATE INDEX IF NOT EXISTS idx_messages_product ON messages(product_id)")


def init_app(app):
    """앱 종료 시 연결을 닫도록 등록."""
    app.teardown_appcontext(close_db)

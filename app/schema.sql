-- 중고거래 플랫폼 데이터베이스 스키마
-- 금액은 원(整数)으로만 저장한다. 부동소수점 오차를 피하기 위함.

PRAGMA foreign_keys = ON;

-- 사용자 --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    display_name  TEXT    NOT NULL,
    bio           TEXT    NOT NULL DEFAULT '',
    balance       INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    role          TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status        TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked')),
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- 로그인 시도 기록 (브루트포스 방어용) --------------------------------------
CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier  TEXT    NOT NULL,   -- 계정명 또는 IP
    attempt_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    success     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_id ON login_attempts(identifier, attempt_at);

-- 상품 ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL,
    price       INTEGER NOT NULL CHECK (price >= 0),
    image_path  TEXT,                 -- instance/uploads 내부 파일명 (NULL 가능)
    category    TEXT    NOT NULL DEFAULT 'etc',
    region      TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'sold', 'blocked')),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id);
CREATE INDEX IF NOT EXISTS idx_products_status ON products(status);
-- idx_products_category 는 category 컬럼 추가 후 db._migrate 에서 만든다
-- (기존 DB는 이 시점에 아직 category 컬럼이 없기 때문).

-- 찜(관심상품) ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS favorites (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, product_id)
);
CREATE INDEX IF NOT EXISTS idx_fav_product ON favorites(product_id);

-- 주문(에스크로) ----------------------------------------------------------
-- 결제하면 'held'(대금 보류) 상태로 시작하고, 구매 확정 시 판매자에게 정산된다.
CREATE TABLE IF NOT EXISTS orders (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id   INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    buyer_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seller_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount       INTEGER NOT NULL CHECK (amount >= 0),
    status       TEXT    NOT NULL DEFAULT 'held'
                 CHECK (status IN ('held', 'confirmed', 'cancelled')),
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    confirmed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_orders_product ON orders(product_id);
CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id);
CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id);

-- 거래 후기(평판) ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS reviews (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id    INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    reviewer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating      INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment     TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(order_id, reviewer_id)
);
CREATE INDEX IF NOT EXISTS idx_reviews_target ON reviews(target_id);

-- 알림 -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text       TEXT    NOT NULL,
    link       TEXT    NOT NULL DEFAULT '',
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, id);

-- 상품별 1:1 메시지 --------------------------------------------------------
-- 대화는 '상품' 단위로 나뉜다. 같은 상대라도 상품이 다르면 다른 대화방이다.
CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id  INTEGER REFERENCES products(id) ON DELETE CASCADE,
    sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, created_at);
-- idx_messages_product 는 product_id 컬럼 추가 후 db._migrate 에서 만든다.

-- 송금 원장 ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transfers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount      INTEGER NOT NULL CHECK (amount > 0),
    memo        TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_transfers_sender ON transfers(sender_id);
CREATE INDEX IF NOT EXISTS idx_transfers_receiver ON transfers(receiver_id);

-- 신고 ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_type   TEXT    NOT NULL CHECK (target_type IN ('user', 'product')),
    target_id     INTEGER NOT NULL,
    reason        TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open', 'resolved', 'dismissed')),
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
-- 같은 사용자가 같은 대상을 중복 신고하지 못하도록 제약
CREATE UNIQUE INDEX IF NOT EXISTS uq_reports_once
    ON reports(reporter_id, target_type, target_id);

"""입력값 검증 헬퍼.

서버는 클라이언트가 보낸 값을 절대 신뢰하지 않는다. HTML 의 maxlength 나
JS 검증은 우회 가능하므로, 여기 있는 함수들이 최종 관문이다.
각 함수는 (정제된 값) 을 돌려주거나 ValueError 를 던진다.
"""
import re

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")

# 필드별 최대 길이. DB 낭비와 서비스 거부(초대형 입력)를 막는다.
LIMITS = {
    "display_name": 30,
    "bio": 300,
    "product_title": 100,
    "product_description": 2000,
    "message_body": 1000,
    "report_reason": 500,
    "transfer_memo": 100,
}

# 금액 상한(원). 정수 오버플로 및 비현실적 값 차단.
MAX_AMOUNT = 100_000_000  # 1억 원


def validate_username(value):
    value = (value or "").strip()
    if not USERNAME_RE.match(value):
        raise ValueError("아이디는 영문/숫자/밑줄 3~20자여야 합니다.")
    return value


def validate_password(value):
    value = value or ""
    if len(value) < 8:
        raise ValueError("비밀번호는 최소 8자 이상이어야 합니다.")
    if len(value) > 128:
        raise ValueError("비밀번호가 너무 깁니다(최대 128자).")
    # 최소한의 복잡도: 문자와 숫자를 모두 포함
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise ValueError("비밀번호는 영문과 숫자를 모두 포함해야 합니다.")
    return value


def validate_text(value, field, *, allow_empty=False):
    """길이 제한이 있는 일반 텍스트. 앞뒤 공백 제거."""
    value = (value or "").strip()
    if not value and not allow_empty:
        raise ValueError("필수 입력값이 비어 있습니다.")
    limit = LIMITS.get(field, 500)
    if len(value) > limit:
        raise ValueError(f"입력이 너무 깁니다(최대 {limit}자).")
    return value


def validate_amount(value):
    """금액을 양의 정수(원)로 변환. 문자열/실수/음수/과대값 모두 거른다."""
    try:
        # 실수 문자열이 들어와도 소수점은 허용하지 않는다.
        if isinstance(value, str):
            value = value.strip().replace(",", "")
        amount = int(value)
    except (TypeError, ValueError):
        raise ValueError("금액은 숫자여야 합니다.")
    if amount <= 0:
        raise ValueError("금액은 1원 이상이어야 합니다.")
    if amount > MAX_AMOUNT:
        raise ValueError("한 번에 보낼 수 있는 금액을 초과했습니다.")
    return amount


def validate_price(value):
    """상품 가격은 0원(나눔) 이상 허용."""
    try:
        if isinstance(value, str):
            value = value.strip().replace(",", "")
        price = int(value)
    except (TypeError, ValueError):
        raise ValueError("가격은 숫자여야 합니다.")
    if price < 0:
        raise ValueError("가격은 0원 이상이어야 합니다.")
    if price > MAX_AMOUNT:
        raise ValueError("가격이 너무 큽니다.")
    return price

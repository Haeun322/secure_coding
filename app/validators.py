"""입력값 검증 헬퍼.

서버는 클라이언트가 보낸 값을 절대 신뢰하지 않는다. HTML 의 maxlength 나
JS 검증은 우회 가능하므로, 여기 있는 함수들이 최종 관문이다.
각 함수는 (정제된 값) 을 돌려주거나 ValueError 를 던진다.
"""
import re

from .constants import CATEGORY_KEYS

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")

# 금액 문자열은 ASCII 숫자만 허용한다. int() 는 전각숫자('１２３')나 유니코드
# 숫자도 받아들이므로, 사용자가 의도하지 않은 값으로 바뀌는 것을 막기 위해 직접 검사한다.
_DIGITS_RE = re.compile(r"^[0-9]+$")
_MAX_NUM_LEN = 15  # 자릿수 상한(초대형 정수 파싱 CPU 낭비 방지)

# 아주 흔한 취약 비밀번호 최소 차단 목록(정책 보조용).
COMMON_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "1234567890",
    "qwerty123", "111111111", "12341234", "abcd1234", "qwer1234",
    "password123", "admin123", "iloveyou1", "welcome1", "1q2w3e4r",
}

# 필드별 최대 길이. DB 낭비와 서비스 거부(초대형 입력)를 막는다.
LIMITS = {
    "display_name": 30,
    "bio": 300,
    "product_title": 100,
    "product_description": 2000,
    "message_body": 1000,
    "report_reason": 500,
    "transfer_memo": 100,
    "review_comment": 300,
    "region": 30,
}

# 금액 상한(원). 정수 오버플로 및 비현실적 값 차단.
MAX_AMOUNT = 100_000_000  # 1억 원


def validate_username(value):
    value = (value or "").strip()
    if not USERNAME_RE.match(value):
        raise ValueError("아이디는 영문/숫자/밑줄 3~20자여야 합니다.")
    return value


def validate_password(value, *, username=None):
    value = value or ""
    if len(value) < 8:
        raise ValueError("비밀번호는 최소 8자 이상이어야 합니다.")
    if len(value) > 128:
        raise ValueError("비밀번호가 너무 깁니다(최대 128자).")
    # 최소한의 복잡도: 문자와 숫자를 모두 포함
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise ValueError("비밀번호는 영문과 숫자를 모두 포함해야 합니다.")
    if value.lower() in COMMON_PASSWORDS:
        raise ValueError("너무 흔한 비밀번호입니다. 다른 비밀번호를 사용하세요.")
    # 아이디를 그대로/포함한 비밀번호 금지
    if username and username.lower() in value.lower():
        raise ValueError("비밀번호에 아이디를 포함할 수 없습니다.")
    return value


def _parse_won(value):
    """금액 공통 파서. ASCII 숫자만, 길이 제한 후 정수 변환.

    '1,000' 처럼 천단위 콤마는 허용하되, '1,2,3' 같은 이상한 콤마 배치나
    전각/유니코드 숫자는 거부해 사용자가 의도한 값과 달라지는 것을 막는다.
    """
    if value is None:
        raise ValueError("금액을 입력하세요.")
    s = str(value).strip()
    # 콤마는 올바른 천단위 구분(1 또는 1,000 또는 12,345,678)일 때만 제거
    if "," in s:
        if not re.match(r"^[0-9]{1,3}(,[0-9]{3})+$", s):
            raise ValueError("금액 형식이 올바르지 않습니다.")
        s = s.replace(",", "")
    if len(s) > _MAX_NUM_LEN:
        raise ValueError("금액이 너무 큽니다.")
    if not _DIGITS_RE.match(s):
        raise ValueError("금액은 숫자여야 합니다.")
    return int(s)


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
    """송금 금액을 양의 정수(원)로 변환. 실수/음수/과대값/이상한 형식을 거른다."""
    amount = _parse_won(value)
    if amount <= 0:
        raise ValueError("금액은 1원 이상이어야 합니다.")
    if amount > MAX_AMOUNT:
        raise ValueError("한 번에 보낼 수 있는 금액을 초과했습니다.")
    return amount


def validate_price(value):
    """상품 가격은 0원(나눔) 이상 허용."""
    price = _parse_won(value)
    if price > MAX_AMOUNT:
        raise ValueError("가격이 너무 큽니다.")
    return price


def validate_category(value):
    """카테고리는 정해진 목록 안에서만 허용(임의 값 저장 방지)."""
    value = (value or "etc").strip()
    if value not in CATEGORY_KEYS:
        raise ValueError("올바른 카테고리를 선택하세요.")
    return value


def validate_region(value):
    """거래 지역(동네). 비워도 되고, 길이만 제한한다."""
    return validate_text(value, "region", allow_empty=True)


def validate_rating(value):
    """후기 별점 1~5."""
    try:
        rating = int(value)
    except (TypeError, ValueError):
        raise ValueError("별점을 선택하세요.")
    if rating < 1 or rating > 5:
        raise ValueError("별점은 1~5 사이여야 합니다.")
    return rating

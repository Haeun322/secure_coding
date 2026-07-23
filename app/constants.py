"""상품 카테고리/정렬 등 고정 상수.

카테고리 키는 DB에 저장하고, 화면에는 한글 라벨을 보여 준다.
정렬은 사용자 입력을 그대로 SQL에 넣지 않고, 여기 정의된 값에만 매핑한다
(ORDER BY 인젝션 방지).
"""

# 저장 키 -> 표시 라벨
CATEGORIES = {
    "digital": "디지털기기",
    "appliance": "생활가전",
    "furniture": "가구/인테리어",
    "clothing": "의류/잡화",
    "book": "도서/티켓",
    "hobby": "취미/게임",
    "etc": "기타",
}
CATEGORY_KEYS = set(CATEGORIES.keys())

# 정렬 키 -> (표시 라벨, 안전한 ORDER BY 절)
SORTS = {
    "recent": ("최신순", "p.created_at DESC, p.id DESC"),
    "price_asc": ("가격 낮은순", "p.price ASC, p.id DESC"),
    "price_desc": ("가격 높은순", "p.price DESC, p.id DESC"),
    "popular": ("인기순(찜)", "fav_count DESC, p.created_at DESC"),
}
DEFAULT_SORT = "recent"


def category_label(key):
    return CATEGORIES.get(key, "기타")

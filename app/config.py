"""애플리케이션 설정.

환경 변수(.env)로 주입되는 값들을 한곳에서 모아 둔다.
비밀키가 지정되지 않은 채로 운영에 올라가는 것을 막기 위해,
개발용 임시 키는 콘솔에 경고를 남기고, 명시적으로 요구할 때만 허용한다.
"""
import os
import secrets


def _load_dotenv(path):
    """의존성 없이 아주 단순한 .env 로더.

    python-dotenv 를 추가로 설치하지 않으려고 직접 구현했다.
    KEY=VALUE 형태의 줄만 읽고, 이미 환경에 있는 값은 덮어쓰지 않는다.
    """
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


class Config:
    # 프로젝트 루트(=app 폴더의 부모)
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def __init__(self):
        _load_dotenv(os.path.join(self.BASE_DIR, ".env"))

        self.SECRET_KEY = os.environ.get("SECRET_KEY")
        if not self.SECRET_KEY:
            # 개발 편의를 위해 자동 생성하되, 재시작하면 세션이 풀린다는 점을 알린다.
            self.SECRET_KEY = secrets.token_hex(32)
            print(
                "[warn] SECRET_KEY 가 설정되지 않아 임시 키를 생성했습니다. "
                "운영 환경에서는 반드시 .env 에 SECRET_KEY 를 지정하세요."
            )

        # instance 폴더: DB 파일과 업로드 파일을 담는다. git 에 올리지 않는다.
        self.INSTANCE_DIR = os.path.join(self.BASE_DIR, "instance")
        self.DATABASE = os.path.join(self.INSTANCE_DIR, "market.sqlite3")
        self.UPLOAD_DIR = os.path.join(self.INSTANCE_DIR, "uploads")

        # 세션 쿠키 보안 옵션
        self.SESSION_COOKIE_HTTPONLY = True          # JS 에서 쿠키 접근 차단(XSS 방어 보조)
        self.SESSION_COOKIE_SAMESITE = "Lax"         # 크로스사이트 전송 제한(CSRF 방어 보조)
        self.SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
        self.PERMANENT_SESSION_LIFETIME = 60 * 60 * 8  # 8시간

        # 업로드 및 요청 크기 제한 (파일 5MB)
        self.MAX_CONTENT_LENGTH = 5 * 1024 * 1024

        # 리버스 프록시(nginx 등) 뒤에 둘 때 신뢰할 프록시 홉 수.
        # 0 이면 프록시 없음(직접 노출). 1 이상이면 X-Forwarded-For 를 그만큼 신뢰해
        # 실제 클라이언트 IP 를 복원한다(레이트리밋이 프록시 IP 하나로 뭉치는 문제 방지).
        try:
            self.TRUST_PROXY_HOPS = int(os.environ.get("TRUST_PROXY_HOPS", "0"))
        except ValueError:
            self.TRUST_PROXY_HOPS = 0

        # 최초 부팅 시 만들 관리자 계정 (선택)
        self.ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
        self.ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

    def as_dict(self):
        return {
            "SECRET_KEY": self.SECRET_KEY,
            "DATABASE": self.DATABASE,
            "UPLOAD_DIR": self.UPLOAD_DIR,
            "INSTANCE_DIR": self.INSTANCE_DIR,
            "SESSION_COOKIE_HTTPONLY": self.SESSION_COOKIE_HTTPONLY,
            "SESSION_COOKIE_SAMESITE": self.SESSION_COOKIE_SAMESITE,
            "SESSION_COOKIE_SECURE": self.SESSION_COOKIE_SECURE,
            "PERMANENT_SESSION_LIFETIME": self.PERMANENT_SESSION_LIFETIME,
            "MAX_CONTENT_LENGTH": self.MAX_CONTENT_LENGTH,
            "TRUST_PROXY_HOPS": self.TRUST_PROXY_HOPS,
            "ADMIN_USERNAME": self.ADMIN_USERNAME,
            "ADMIN_PASSWORD": self.ADMIN_PASSWORD,
        }

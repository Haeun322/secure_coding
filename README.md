# 중고거래 플랫폼 (Secure Marketplace)

보안 프로그래밍 과제로 만든 중고거래 플랫폼입니다. 회원가입, 상품 등록·검색,
1:1 메시지, 사용자 간 송금, 신고·차단, 관리자 콘솔을 제공하며, 웹 애플리케이션에서
흔한 취약점(SQL Injection, XSS, CSRF, 접근 통제 미흡, 파일 업로드, 무차별 대입 등)을
막는 데 초점을 맞췄습니다.

- 언어/프레임워크: **Python 3.11+ / Flask 3.1 / SQLite**
- 런타임 의존성: `Flask`, `Werkzeug` 두 개뿐 (CSRF·레이트리밋·검증은 표준 라이브러리로 직접 구현)
- 개발 과정과 보안 대응 상세는 [docs/REPORT.md](docs/REPORT.md) 참고

## 주요 기능

| 기능 | 설명 |
|---|---|
| 회원 | 가입 / 로그인 / 로그아웃 / 프로필·비밀번호 변경 |
| 상품 | 등록·수정·삭제, 이미지 업로드, 목록·상세, 키워드 검색 |
| 소통 | 사용자 간 1:1 메시지 |
| 송금 | 지갑 잔액, 사용자 간 이체(원자적 처리), 거래 내역 |
| 신고·차단 | 유저/상품 신고, 신고 누적 시 자동 숨김, 관리자 차단 |
| 관리자 | 사용자·상품·신고·송금 전체 관리 |

## 요구 환경

- Python 3.11 이상 (개발·검증은 3.14에서 진행)
- pip
- OS 무관 (Windows / macOS / Linux). 아래 명령은 OS별로 나눠 적었습니다.

## 설치 및 실행

### 1) 소스 내려받기

```bash
git clone https://github.com/<your-account>/secure-marketplace.git
cd secure-marketplace
```

### 2) 가상환경 만들기 (권장)

**Windows (PowerShell)**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3) 의존성 설치

```bash
pip install -r requirements.txt
```

### 4) 환경변수 설정 (`.env`)

`.env.example`을 복사해서 `.env`를 만들고 값을 채웁니다.

**Windows (PowerShell)**
```powershell
Copy-Item .env.example .env
```

**macOS / Linux**
```bash
cp .env.example .env
```

그다음 무작위 `SECRET_KEY`를 만들어 `.env`에 넣습니다.

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

`.env` 예시:

```
SECRET_KEY=여기에_위에서_생성한_64자리_hex
SESSION_COOKIE_SECURE=0
ADMIN_USERNAME=admin
ADMIN_PASSWORD=ChangeThisAdminPw!234
```

- `SECRET_KEY`: 세션/CSRF 서명 키. **반드시 무작위 값으로 교체**하세요.
- `SESSION_COOKIE_SECURE`: HTTPS로 서비스하면 `1`, 로컬 개발이면 `0`.
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`: 최초 실행 시 관리자 계정이 자동 생성됩니다.
  (비밀번호는 8자 이상, 영문+숫자 포함) 생성 후에는 이 두 값을 지워도 됩니다.

> `.env`는 `.gitignore`에 등록되어 있어 저장소에 올라가지 않습니다.

### 5) 서버 실행

```bash
python run.py
```

브라우저에서 http://127.0.0.1:5000 접속.
데이터베이스(`instance/market.sqlite3`)는 첫 실행 때 자동으로 만들어집니다.

관리자로 로그인하려면 `.env`에 설정한 `ADMIN_USERNAME`/`ADMIN_PASSWORD`로 로그인한 뒤,
상단 메뉴의 **관리자**로 들어가면 됩니다.

## 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

20개의 통합 테스트가 기능과 보안 동작(CSRF, SQLi, XSS, 접근 통제, 송금 안전성,
레이트리밋 등)을 검증합니다.

## 빠른 사용 순서

1. 회원가입 → 로그인
2. **지갑**에서 데모 충전 → 다른 사용자에게 **송금**
3. **상품등록**으로 물건 올리기 → 상단 검색으로 찾기
4. 상품 상세에서 **판매자와 대화**(메시지)
5. 이상한 유저/상품은 **신고** → 관리자가 관리자 콘솔에서 처리

## 배포 시 주의 (운영 환경)

- 개발 서버(`python run.py`) 대신 WSGI 서버를 사용하세요.
  ```bash
  pip install waitress
  waitress-serve --port=8000 "app:create_app()"
  ```
- 반드시 HTTPS를 적용하고 `.env`의 `SESSION_COOKIE_SECURE=1`로 설정하세요.
- `SECRET_KEY`는 환경별로 다른 무작위 값을 사용하세요.

## 프로젝트 구조

```
secure_coding/
├── run.py                # 실행 진입점
├── requirements.txt      # 런타임 의존성
├── requirements-dev.txt  # 테스트 의존성
├── .env.example          # 환경변수 예시
├── README.md
├── docs/
│   └── REPORT.md         # 개발 보고서(요구분석~유지보수, 보안 대응)
├── app/
│   ├── __init__.py       # 앱 팩토리
│   ├── config.py         # 설정/환경변수
│   ├── db.py             # SQLite 연결
│   ├── schema.sql        # DB 스키마
│   ├── security.py       # CSRF·인증·레이트리밋·보안헤더
│   ├── validators.py     # 입력 검증
│   ├── blueprints/       # 기능별 라우트
│   ├── templates/        # Jinja2 템플릿
│   └── static/style.css
└── tests/                # pytest 통합 테스트
```

## 라이선스

학습/과제 목적의 프로젝트입니다.

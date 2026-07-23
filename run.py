"""개발 서버 실행 진입점.

    python run.py

운영 배포는 gunicorn/waitress 같은 WSGI 서버 뒤에 두는 것을 권장한다.
    waitress-serve --port=5000 "app:create_app()"
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug=False 로 둔다. 디버그 모드는 스택트레이스/콘솔 노출로 정보 유출 위험이 있다.
    app.run(host="127.0.0.1", port=5000, debug=False)

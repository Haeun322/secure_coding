"""REPORT.md 를 인쇄용(PDF 저장용) HTML 로 변환한다.

    python docs/build_report_html.py

만들어진 docs/REPORT.html 을 크롬/엣지에서 열고 Ctrl+P → 대상 'PDF로 저장' 하면
제출용 PDF가 나온다. (별도 PDF 도구 설치 불필요)
"""
import os
import markdown

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "REPORT.md")
OUT = os.path.join(HERE, "REPORT.html")

CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body {
  font-family: "Malgun Gothic", "맑은 고딕", system-ui, sans-serif;
  color: #1f2328; line-height: 1.65; font-size: 10.5pt; margin: 0;
  max-width: 800px; padding: 24px; margin-left: auto; margin-right: auto;
}
h1, h2, h3 { line-height: 1.3; }
h1 { font-size: 20pt; border-bottom: 3px solid #4c8f3f; padding-bottom: 8px; }
h2 { font-size: 15pt; margin-top: 26px; border-bottom: 1px solid #d7dbe0; padding-bottom: 5px; }
h3 { font-size: 12pt; margin-top: 18px; }
p, li { font-size: 10.5pt; }
code {
  font-family: Consolas, "D2Coding", monospace; font-size: 9.5pt;
  background: #f3f4f6; padding: 1px 4px; border-radius: 4px;
}
pre {
  background: #f6f8fa; border: 1px solid #e2e5e9; border-radius: 6px;
  padding: 10px 12px; overflow-x: auto;
}
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 9.5pt; }
th, td { border: 1px solid #cfd4da; padding: 6px 9px; text-align: left; vertical-align: top; }
th { background: #eef2f5; }
tr, table, pre, h1, h2, h3 { page-break-inside: avoid; }
h1, h2, h3 { page-break-after: avoid; }
hr { border: none; border-top: 1px solid #d7dbe0; margin: 20px 0; }
blockquote { color: #57606a; border-left: 3px solid #cfd4da; margin: 8px 0; padding: 2px 12px; }
a { color: #1a5fd0; text-decoration: none; }
"""

def main():
    with open(SRC, "r", encoding="utf-8") as fh:
        text = fh.read()
    body = markdown.markdown(
        text, extensions=["tables", "fenced_code", "sane_lists"]
    )
    html = (
        "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
        "<title>중고거래 플랫폼 개발 보고서</title>"
        f"<style>{CSS}</style></head><body>{body}</body></html>"
    )
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"생성됨: {OUT}")


if __name__ == "__main__":
    main()

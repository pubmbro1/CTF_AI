# Web 분석 가이드

============================================================
## Web 코드 리딩 체크포인트
============================================================

초기 분석 시 아래 8개 관점을 반드시 확인한다.
해당 사항이 있으면 분석 패킷에 기록한다.

**① 입력 경계면 (Entry Points)**
- 어떤 경로로 사용자 입력이 들어오는가? (body, query, header, cookie, file upload, WebSocket)
- 파서 설정 확인: 파서 종류와 옵션에 따라 같은 입력도 다르게 해석됨
- 타입 처리: 문자열이 숫자/배열/객체로 변환되는 지점, 암묵적 형변환

**② 출력 지점 (Sink Points)**
- HTML/템플릿 출력: escape 여부 확인 (escaped vs unescaped 구문 구분)
- 서버 사이드 렌더링: PDF, 이미지, 이메일 등 서버에서 콘텐츠를 생성/렌더하는 기능
  → 서버 컨텍스트에서 실행되므로 내부 네트워크 접근, 로컬 파일 접근 가능성
- 시스템 명령어: exec, system, popen 등에 입력이 전달되는 경로
- DB 쿼리: prepared statement 사용 여부, 문자열 결합으로 쿼리 생성하는 부분
- 로그/파일 기록: 입력이 파일에 쓰이는 경우 (log injection, 파일 내용 조작)

**③ 서버→서버 통신 (Server-Side Requests)**
- 서버가 외부/내부 서비스로 요청을 보내는 모든 코드
- 그 요청의 URL, header, body에 사용자 입력이 포함되는가?
- URL 문자열 직접 삽입 → parameter injection, path injection, SSRF
- 응답을 신뢰하고 그대로 사용하는가? → 응답 데이터 조작 가능성
- 내부 서비스의 소스가 미제공이면 → 정보 수집 우선 원칙 적용

**④ 인증/권한 (Auth & Access Control)**
- 인증 방식과 약점: 토큰 알고리즘, 시크릿 강도, 서명 검증 로직
- 라우트별 인증 미들웨어 적용 여부 — 미적용 라우트가 있는지 전수 확인
- 수직 권한 상승: 일반 사용자가 관리자 기능에 접근 가능한 경로
- 수평 권한 상승: 다른 사용자의 리소스에 접근 가능한 경로 (IDOR)
- 클라이언트 제공 값(role, admin, id 등)을 서버가 그대로 신뢰하는 부분

**⑤ 동시성 / 상태 변경 (Race & State)**
- "확인 → 실행" 사이에 시간 간격이 있는 모든 패턴 (TOCTOU)
- 명시적 지연(sleep, delay) 뿐 아니라 비동기 I/O, 외부 API 호출 등 암묵적 지연도 포함
- 다단계 상태 변경이 하나의 트랜잭션으로 묶이지 않은 경우
- 파일 생성/삭제, 세션 변경, 잔액/포인트 조작 등 상태 변경 연산 전반

**⑥ 데이터 구조 조작 (Data Structure Abuse)**
- 사용자 입력으로 객체/dict 키를 제어 가능한가? → 키 덮어쓰기, prototype pollution
- 문자열 파싱(split, regex 등)에서 구분자/패턴 조작 가능성
- 타입 비교 불일치: strict vs loose, 문자열↔숫자 변환, NaN/Infinity 처리
- 직렬화/역직렬화: pickle, yaml.load, JSON.parse 등에서 객체 조작

**⑦ 파일 시스템 접근 (File Operations)**
- 사용자 입력이 파일 경로에 포함되는가? → path traversal (../, %2e%2e/)
- 파일 업로드: 확장자/MIME 검증 방식, 저장 경로, 실행 가능 여부
- 파일 다운로드/읽기: 접근 제어 없이 경로만으로 파일을 반환하는 엔드포인트
- 임시 파일 생성/삭제: 예측 가능한 파일명, 삭제 전 접근 가능 여부

**⑧ 설정 / 환경 (Configuration & Environment)**
- debug 모드 활성화 여부 (상세 에러, 스택 트레이스, 소스 노출)
- 기본/하드코딩된 credential (admin/admin, secret key 고정값 등)
- 환경변수로 주입되는 값: HOST, PORT, SECRET 등 → 내부 구조 힌트
- 주석 처리된 코드: 비활성 기능이지만 내부 API 구조, 엔드포인트 힌트를 노출

============================================================
## Web RCE 공통 패턴
============================================================

코드 실행 벡터 발견 시 즉시 적용한다.

**ⓐ 샌드박스 우회 — require 접근 불가 시**
- new Function(), vm.runInNewContext(), eval 등 격리된 스코프에서 require가 없을 때:
  → `process.mainModule.require('child_process')`
  → `process.binding('spawn_sync')`
  → `global.process.mainModule.constructor._load`
  → `import()` (ESM 환경)
- 위 순서로 시도. 첫 번째 성공하면 나머지 불필요.

**ⓑ 실행-결과 분리 (Blind Execution → Exfiltration)**
- 코드 실행은 되지만 반환값/출력을 직접 받을 수 없는 경우:
  → 2단계 패턴: ① 함수/변수/테이블에 결과 저장 → ② 별도 쿼리로 결과 조회
  → 또는 세미콜론(;)으로 실행문+조회문 체이닝
  → OOB(Out-of-Band): DNS exfil, HTTP callback 등은 최후 수단
- "실행됐는데 결과가 안 보이면, 저장 후 조회 패턴을 먼저 시도하라"

**ⓒ SQL 엔진 abuse (SQL → RCE)**
- SQL 엔진이 JS/Python/Lua 등 스크립트 실행을 지원하는 경우 → RCE 벡터
- 대표 사례: alasql(`JS`), SQLite load_extension, PostgreSQL COPY PROGRAM
- 엔진별 특수 구문을 소스에서 먼저 확인 (파서 규칙, 토큰 목록 등)

끝.

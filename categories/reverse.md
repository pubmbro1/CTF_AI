# Reverse 분석 가이드

============================================================
## 초기 분석 루틴
============================================================

바이너리가 주어지면 즉시 수행:
```
file chall
strings chall | grep -E '(flag|key|password|correct|wrong)'
checksec --file=chall
```

**분석 방향 결정:**
- 심볼 있음 → 함수명으로 핵심 로직 빠르게 탐색
- 심볼 없음(stripped) → entry point부터 흐름 추적
- 패킹/난독화 → UPX 여부 확인 (`upx -d chall`), entropy 확인

============================================================
## 정적 분석
============================================================

**IDA / Ghidra 흐름:**
1. main() 또는 entry point 진입
2. 입력 받는 함수 탐색 (scanf, fgets, read, gets)
3. 비교 함수 탐색 (strcmp, memcmp, strncmp)
4. 핵심 검증 로직 파악
5. 역연산 또는 constraint 추출

**핵심 패턴:**
- 단순 비교: `strcmp(input, flag)` → strings로 flag 직접 추출 가능
- 변환 후 비교: input을 변환 → 변환 함수 역연산
- 반복 검증: 바이트별 XOR/ADD/SUB → 역연산으로 key 복원
- VM 구조: 가상 명령어 세트 → opcode 분석 후 디어셈블

============================================================
## 동적 분석
============================================================

```
gdb -q ./chall
pwndbg> break *main
pwndbg> run
pwndbg> disas          # 현재 함수 디어셈블
pwndbg> ni / si        # 명령어 단위 실행
pwndbg> x/s 0xaddr     # 문자열 확인
pwndbg> x/20gx $rsp    # 스택 확인
pwndbg> watch *0xaddr  # 특정 주소 값 변경 감지
```

**strace / ltrace 활용:**
```
strace ./chall          # 시스템 콜 추적
ltrace ./chall          # 라이브러리 콜 추적 (strcmp 등 노출)
```

============================================================
## 알고리즘 식별
============================================================

**상수로 알고리즘 특정:**
- `0x67452301, 0xEFCDAB89` → MD5
- `0x6A09E667` → SHA-256
- `0x9E3779B9` → TEA/XTEA
- S-box 테이블 → AES 또는 커스텀 치환

**식별 도구:**
- IDA FLIRT signatures
- `findcrypt` 플러그인 (IDA/Ghidra)
- binwalk entropy 분석

============================================================
## Constraint Solving (z3)
============================================================

검증 로직이 복잡한 수식일 때:

```python
from z3 import *

flag = [BitVec(f'c{i}', 8) for i in range(FLAG_LEN)]
s = Solver()

# 역어셈블한 조건 추가
s.add(flag[0] ^ 0x41 == 0x12)
# ...

if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in flag))
```

============================================================
## Overanalysis Guard
============================================================

아래 조건 충족 시 추가 분석 중단 → flag 제출:
- 역연산 로직 완성
- 전체 flag 바이트 복원 완료
- 프린터블 문자 + flag 포맷 일치
- 재검증(바이너리에 입력) 성공

끝.

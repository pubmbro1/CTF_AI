# Pwn 분석 가이드

============================================================
## 초기 분석 루틴
============================================================

바이너리가 주어지면 즉시 수행:
```
checksec --file=chall
file chall
strings chall | grep -E '(flag|sh|bin|cat|system|exec)'
./chall   # 기본 동작 확인
```

보호 기법 확인 후 공격 가능한 벡터를 먼저 나열한다:
- **No PIE + No RELRO** → GOT overwrite 가능
- **No Canary** → Stack overflow → RIP 직접 제어
- **No NX** → Shellcode 실행 가능
- **Partial RELRO + PIE** → libc leak 후 ROP 필요

============================================================
## 취약점 유형별 분석
============================================================

**Stack Buffer Overflow**
- 입력 크기 vs 버퍼 크기 비교
- RBP/RIP까지의 오프셋 계산: `cyclic` 또는 `pattern_create`
- canary 존재 시 → canary leak 경로 탐색 (format string, read 등)

**Format String Bug**
- `printf(buf)` 형태 탐색 — 인자 없이 user input이 직접 전달되는 곳
- 스택 오프셋 확인: `%p.%p.%p...`
- libc/canary/PIE base leak: `%N$p`
- arbitrary write: `%N$n`

**Heap Exploitation**
- malloc/free 패턴 확인
- UAF(Use After Free): free 이후 포인터 재사용 여부
- Double Free: 같은 chunk를 두 번 free하는 경로
- Heap overflow: chunk 경계 넘는 쓰기 가능 여부
- tcache/fastbin/smallbin 상태 파악 (gdb `heap` 명령)

**Integer Overflow / Signedness**
- 크기 비교에 signed/unsigned 혼용 여부
- size_t vs int 비교에서 음수 값이 큰 양수로 변환되는 경로
- 곱셈/덧셈 overflow로 할당 크기가 작아지는 경우

============================================================
## 정보 수집 (leak) 전략
============================================================

PIE/ASLR 환경에서는 반드시 주소 leak을 먼저 확보한다.

**libc base leak:**
- puts/printf로 GOT 주소 출력
- format string으로 스택의 libc 주소 읽기
- `libc.address = leaked_addr - libc.sym['함수명']`

**libc 버전 특정:**
- `strings libc.so.6 | grep 'GNU C'`
- leak된 주소 마지막 3nibble로 libc-database 검색

**PIE base leak:**
- format string으로 스택의 코드 영역 주소 읽기
- 실행 파일 내 함수 주소 leak

============================================================
## ROP 체인 구성
============================================================

```python
from pwn import *

elf = ELF('./chall')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# 가젯 탐색
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]

# one_gadget 사용 시
# one_gadgets = [0x..., 0x..., 0x...]
```

**공통 패턴:**
- `pop rdi; ret` → rdi에 인자 설정
- `ret` 정렬 가젯 → Ubuntu 18.04+ movaps 정렬 이슈 해결
- system("/bin/sh") 또는 one_gadget

============================================================
## GDB 루틴
============================================================

```
gdb -q ./chall
pwndbg> cyclic 200          # 패턴 생성
pwndbg> run <<< $(cyclic 200)
pwndbg> cyclic -l 0x6161616b  # 오프셋 계산
pwndbg> x/20gx $rsp         # 스택 확인
pwndbg> vmmap               # 메모리 맵
pwndbg> got                 # GOT 테이블
pwndbg> heap                # 힙 상태
pwndbg> telescope $rsp 30   # 스택 체인 추적
```

============================================================
## Exploit 템플릿
============================================================

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# p = process('./chall')
p = remote('host', port)
elf = ELF('./chall')
libc = ELF('./libc.so.6')

def exploit():
    # 1. leak
    # 2. 오프셋 계산
    # 3. payload 구성
    # 4. 전송
    p.interactive()

exploit()
```

============================================================
## Pwn Deep Analysis
============================================================

### Primitive 식별 (공격 가능한 원시 능력 분류)

exploit 전략 수립 전에 현재 확보 가능한 primitive를 먼저 분류한다:

| Primitive | 확보 방법 | 의미 |
|-----------|-----------|------|
| Arbitrary Read | fmt string `%s`, OOB read | 임의 주소 읽기 |
| Arbitrary Write | fmt string `%n`, OOB write | 임의 주소 쓰기 |
| Leak (주소 노출) | puts(GOT), printf, fmt | ASLR/PIE 우회 |
| Control RIP | stack overflow, GOT overwrite | 실행 흐름 제어 |

→ 확보된 primitive 조합으로 공격 경로를 설계한다

### GOT / PLT 분석

```
pwndbg> got           # GOT 테이블 전체 확인
pwndbg> plt           # PLT 엔트리 확인
readelf -r chall      # relocation 테이블
```

- RELRO 없음 / Partial → GOT overwrite 가능
- Full RELRO → GOT 읽기는 가능, 쓰기 불가 → 다른 primitive 필요

### Stack vs Heap 분리 판단

**Stack 공격 조건:**
- 지역 변수 버퍼에 입력
- 함수 호출 후 return → RIP 제어

**Heap 공격 조건:**
- malloc/calloc으로 동적 할당된 버퍼에 입력
- 청크 관리 구조(fd, bk, size) 조작 필요

→ 두 영역을 혼동하지 않는다. `vmmap`으로 주소 범위 먼저 확인

### libc 버전 추론 (바이너리 제공 없을 때)

```python
# leak된 주소의 하위 3nibble로 오프셋 특정
# 예: leaked puts = 0x7f...d80 → puts offset 0xd80인 libc 탐색
# https://libc.blukat.me 또는 libc-database
```

```bash
# 로컬에 libc 있을 때
strings libc.so.6 | grep 'GNU C Library'
readelf -s libc.so.6 | grep ' puts@@'
```

============================================================
## Overanalysis Guard
============================================================

아래 조건 충족 시 추가 분석 중단 → exploit 전송:
- 오프셋 확정
- leak 주소 확보 및 base 계산 완료
- payload 역검증 성공 (로컬 동작 확인)
- 원격 연결 준비 완료

끝.

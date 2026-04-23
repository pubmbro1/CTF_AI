# Crypto 분석 가이드

============================================================
## 초기 분석 루틴
============================================================

암호화 문제가 주어지면 즉시 확인:
- 알고리즘 식별 (AES/RSA/ECC/XOR/custom 등)
- 키/IV 크기 및 위치
- 암호화 모드 (ECB/CBC/CTR/GCM 등)
- 상수값 (magic bytes, S-box, 라운드 수)
- 입출력 패턴 (평문-암호문 쌍 제공 여부)

============================================================
## 알고리즘별 공격 벡터
============================================================

**RSA**
- n이 작거나 e가 작은 경우 → small e attack, Wiener's attack
- 같은 n으로 여러 암호문 → common modulus attack
- n 인수분해 가능 여부 → factordb, Fermat factorization (p, q가 가까운 경우)
- LSB oracle → parity oracle attack
- padding → PKCS#1 v1.5 padding oracle

**AES**
- ECB 모드 → 블록 패턴 분석, chosen-plaintext (block 경계 조작)
- CBC 모드 → IV 조작, padding oracle, bit-flipping
- CTR 모드 → 같은 키+IV 재사용 시 keystream XOR
- GCM 모드 → nonce 재사용 시 key recovery

**XOR / 스트림 암호**
- 키 길이 특정: Index of Coincidence, Kasiski test
- 키 길이 알면 → frequency analysis
- 같은 키로 두 평문 암호화 → crib-dragging

**Hash**
- Length extension attack (SHA1/SHA256 + secret prefix)
- Hash collision (MD5: chosen-prefix collision)
- Rainbow table (짧은 입력, unsalted)

**ECC (타원곡선)**
- 같은 nonce k 재사용 → ECDSA nonce reuse attack (두 서명에서 k, private key 복원)
- 잘못된 곡선 파라미터 → invalid curve attack
- 작은 subgroup → small subgroup attack
- nonce가 편향됨 → Lattice attack (HNP, Hidden Number Problem)
- 구현 취약점: scalar multiplication 중 side-channel

**Custom / 알 수 없는 알고리즘**
- 상수 확인 → 알려진 알고리즘의 변형 가능성
- 역연산 가능 여부 파악
- z3 solver로 constraint 풀기

============================================================
## Crypto Overanalysis Guard
============================================================

다음 중 3개 이상 만족하면 분석 종료 → flag 조합 시도:
- 복호화 결과 완전 printable
- padding 구조 완벽
- 재암호화 시 원본과 정확히 일치
- 길이 구조 정확히 일치
- 저장 구조와 논리적 합치

충족 시:
- 추가 모드 탐색 금지
- ECB/CTR/CFB 무작위 대입 금지
- 키/IV brute-force 금지
- state machine 과도 분석 금지

============================================================
## 유용한 도구 및 라이브러리
============================================================

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from sympy import factorint, isprime
from z3 import *

# RSA 기본
n, e, c = ...
# small e (e=3): m = iroot(c, 3)
# factordb: http://factordb.com

# AES padding oracle 템플릿
# CBC bit-flipping: C[i] XOR delta → P[i+1] XOR delta
```

**온라인 도구:**
- factordb.com — RSA n 인수분해
- dcode.fr — 고전 암호 분석
- cyberchef — 범용 변환/분석
- sagemath — 수학적 공격

끝.

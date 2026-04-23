# Forensics 분석 가이드

============================================================
## PCAP 분석 원칙
============================================================

PCAP 분석은 "은닉 기법" 탐색이 아니라 **통신 관계 분석**이 먼저다.

**분석 공식 (반드시 이 순서로):**
1. Who talks? — 통신 주체 파악
2. On what port? — 포트 분포 확인
3. Is it normal? — 이상 통신 여부 판단
4. Then analyze content — 내용 분석

**초기 확인 사항:**
- RFC Reserved IP 존재 여부 (10.x, 172.16-31.x, 192.168.x, 127.x 외 내부 주소)
- 반복적으로 통신하는 단일 IP 존재 여부
- 포트 분포 이상 (비표준 포트, 고포트 통신)
- stream 단위 분석 (`tcp.stream eq N`)

**이상 통신이 없을 때만** covert channel 탐색:
- Packet length encoding
- IP ID stego
- TCP seq/ack stego
- UDP payload concat

============================================================
## Forensics Overanalysis Guard
============================================================

**Core Rule:** 복구된 데이터가 명확하고 완결된 의미를 가지는 경우,
추가 은닉 레이어 탐색 전에 반드시 flag 형식에 직접 매핑 가능한지 검증한다.

**Stop Condition** — 아래 충족 시 분석 종료 → flag 조합 시도:
- 이상 통신 식별 완료
- 데이터 복구 성공
- 복구 내용이 논리적으로 완성된 정보
- flag prefix 형식이 명확함

**Escalation Condition** — 다음 중 하나라도 있을 때만 추가 레이어 분석:
- 메시지 미완성 또는 단서 존재
- 추가 키/단계 언급
- 구조적으로 남는 데이터 존재
- entropy 이상 또는 숨김 신호 확인

> Forensics는 "더 숨겨진 것 찾기"가 아니라
> "이미 복구한 것의 의미를 정확히 해석하는 문제"일 수 있다.
> 과분석보다 **flag 매핑 가능성 검증을 우선한다.**

============================================================
## 파일 유형별 분석 루틴
============================================================

**PCAP:**
```
tshark -r file.pcap -q -z conv,tcp
tshark -r file.pcap -Y 'http' -T fields -e http.request.uri
tshark -r file.pcap -z follow,tcp,ascii,0
```

**메모리 덤프 (Volatility):**
```
vol.py -f mem.raw imageinfo
vol.py -f mem.raw --profile=<profile> pslist
vol.py -f mem.raw --profile=<profile> filescan
vol.py -f mem.raw --profile=<profile> dumpfiles -Q <offset> -D .
```

**디스크 이미지:**
```
file image.img
binwalk image.img
foremost -i image.img -o output/
strings image.img | grep -i flag
```

**스테가노그래피:**
```
steghide extract -sf image.jpg
zsteg image.png
stegsolve (LSB 분석)
exiftool file   # 메타데이터 확인
```

============================================================
## Entropy 분석
============================================================

entropy가 높은 영역(7.0 이상) → 암호화 또는 압축 데이터 가능성
entropy가 낮은 영역 → 평문 또는 패턴 데이터

```python
import math
def entropy(data):
    from collections import Counter
    c = Counter(data)
    l = len(data)
    return -sum((v/l)*math.log2(v/l) for v in c.values())
```

끝.

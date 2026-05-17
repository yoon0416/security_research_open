# Security Research (Public)

DFIR(Digital Forensics & Incident Response) 및 Offensive Security 연구 프로젝트의 공개 요약본.

본 레포는 연구 개요만 공개하며, 분석 스크립트, 추출 코드, 아티팩트 샘플, 상세 기술 문서는 비공개 저장소에서 별도 관리된다.

빠른 커밋/푸시, PoC 구현, 코드 리뷰, 연구 문서 작성에 **Claude Code (Anthropic)**를 활용하고 있다.

---

## Table of Contents

| #   | 프로젝트                                                                        | 분류               | 대상 환경                | 상태                       |
| --- | --------------------------------------------------------------------------- | ---------------- | -------------------- | ------------------------ |
| 1   | [Red Team Artifact — Browser + macOS](#1-red-team-artifact--browser--macos) | Offensive        | Windows / macOS      | macOS Chrome 전 트랙 검증 완료  |
| 2   | [Forensic Artifact Research](#2-forensic-artifact-research)                 | DFIR + Offensive | Windows / macOS      | AI 대화 복구, 메신저 추출, 힙 메모리 잔존 실증 |
| 3   | [BLE Surveillance Radar](#3-ble-surveillance-radar--capability-study)       | Offensive        | iOS (iPhone) + macOS | iPhone 전환 완료 (ARKit + BLE + 나침반) |
| 4   | [iOS AFU Imaging Research](#4-ios-afu-imaging-research)                     | Offensive / DFIR | iOS                  | **USB + 페어링만으로 실 데이터 추출 달성 — iOS 26.4.2 미패치 확정** |
| 5   | [iOS Backup Forensic Research](#5-ios-backup-forensic-research)             | DFIR             | iOS encrypted backup | 79개 앱 중 15개 분석 완료. 보호 모델별 9개 paradigm 도출 — 진행 중 |

- [Upcoming Research](#upcoming-research)
- [Non-Public](#non-public)
- [Disclaimer](#disclaimer)

---

## 1. Red Team Artifact — Browser + macOS

**대상 환경**: Windows / macOS

침투 후(post-compromise) 브라우저 및 macOS 시스템 데이터를 기반으로 크리덴셜 수집, 세션 하이재킹, 피해자 프로파일링, n차 공격 가능 여부를 검증하는 레드팀 프로젝트. 브라우저 아티팩트(Chrome·Safari·Edge)에서 시작하여 macOS 저레벨 아티팩트(Biome·MILO·DuetExpertCenter·Daemon Containers), BLE 패시브 스캔, Apple Intelligence 흔적까지 범위를 확장했다.

단순 파일 수집에 그치지 않고, 수집한 아티팩트를 실제 공격 시나리오(세션 재사용, 계정 탈취, 2차 피싱, 내부망 이동, 물리 위치 재구성, 디바이스 정찰)로 연결하는 **공격 체인 검증**까지를 범위로 한다.

### 수집 범위 (50종+)

| 카테고리 | 주요 아티팩트 |
|--------|-----------|
| 크리덴셜 | 저장 비밀번호, 세션 쿠키, 신용카드 메타데이터 |
| PII/행동 | 자동완성, 방문 URL, 검색어, 다운로드 이력, 북마크 |
| 확장 프로그램 | 설치 목록, 위험 권한 분류, 확장 저장소 민감 데이터 |
| OS 행동 인텔리전스 | 앱 실행 타임라인, 통화/메시지 메타데이터, 미디어 재생, 시맨틱 위치, Siri/AI 질의, 인물 지식 그래프 |
| 물리 위치 (GPS 없이) | Wi-Fi BSSID 핑거프린팅, MILO indoor positioning, 화면 잠금/해제 타임스탬프, 분 단위 근무 패턴 |
| BLE 패시브 스캔 | 100m 반경 Apple/Samsung/LG 디바이스, 벽 투과, 시리얼·펌웨어·Find My 그룹 ID 평문, 행동 토글 추적 |
| Apple Intelligence | Siri NLR 호출 이력, GenerativeFunctions 실행 체인, AI 대화 ID 잔존 |
| Apple ID 인프라 | DSID, IDS push token, alloy.nearby BLE 핸들 (이메일·전화 평문) |
| 삭제 후 복구 | WAL/SHM 페이지, 클립보드 이력, 키보드 단축어, AI 대화 ID (다중 소스 교차 복원) |

현재 macOS Chrome 환경에서 전 트랙 검증 완료.

---

## 2. Forensic Artifact Research

**대상 환경**: Windows / macOS

포렌식 관점에서 브라우저, 메신저, 애플리케이션의 로컬 아티팩트를 분석하는 연구 묶음. AI 대화 흔적 복구, 메신저 데이터 추출, 힙 메모리 잔존 분석을 포함한다.

### 2-A. AI Artifact Extraction — Cross-Browser Analysis

브라우저에서 사용한 생성형 AI 서비스의 대화 본문, 파일 업로드, 계정 정보 등 아티팩트가 로컬에 어떤 형태로 잔존하는지 탐색하는 연구.

**분석 대상**: ChatGPT, Gemini, Claude, Grok, Copilot, Perplexity, Google AI Studio

| 서비스        | macOS Chrome | macOS Safari | Windows Chrome | Windows Edge |
| ---------- | ------------ | ------------ | -------------- | ------------ |
| ChatGPT    | 복구 가능        | 복구 가능        | 복구 가능          | 복구 가능        |
| Claude     | 복구 가능        | 연구 중         | 연구 중           | 연구 중         |
| Grok       | 복구 가능        | 연구 중         | 연구 중           | 연구 중         |
| Perplexity | 복구 가능        | 복구 가능        | 연구 중           | 연구 중         |
| Copilot    | 연구 중         | 연구 중         | 연구 중           | 연구 중         |
| Gemini     | 연구 중         | 연구 중         | 연구 중           | 연구 중         |

### 2-B. Messenger Artifact Analysis

메신저 애플리케이션이 로컬에 남기는 대화 내용, 파일 전송 이력, 계정 정보, 세션 데이터 탐색. Discord, Slack 전 아티팩트 추출 완료.

### 2-C. Heap Memory Residue Research

침해 이후(post-compromise) 애플리케이션이 힙/RAM 영역에 남기는 민감 정보의 평문 잔존 여부, 잔존 형태, 지속성, 노출 범위를 실증 분석.

---

## 3. BLE Surveillance Radar — Capability Study

**대상 환경**: iOS (iPhone) + macOS (대시보드)

iPhone 1대에 내장된 모든 센서(BLE + ARKit + 나침반 + GPS + UWB)를 사용하여 **웨어러블(스마트워치·이어폰)이나 스마트폰을 소지한 주변 사람들**의 위치 추적, 좌표 산출, 방향 파악, 행동 관찰, 행위 추측을 수행하는 능력 연구.

### 주요 특징

| 특징               | 설명                                                                |
| ---------------- | ----------------------------------------------------------------- |
| **불특정 다수 관찰**    | 반경 100m 내 BLE 디바이스 소지자 전원 동시 자동 식별 (벤더 무관)                       |
| **벽 투과**         | BLE/Wi-Fi 신호는 벽·바닥·천장 통과 — 옆집, 위층, 아래층 사람도 감지                    |
| **신원 식별**        | 디바이스 이름 평문, 모델, 시리얼, 벤더 자동 추출 → 소유자 특정 가능                        |
| **행동 관찰**        | AirDrop UI 활성, Hotspot ON/OFF, Share Audio 등 디바이스 사용 행동 시점별 자동 감지 |

### 현재 진행 상황

iPhone iOS 앱 v0.3.0 빌드 완료 — 3탭 UI (Map / Radar / List), ARKit + CoreBluetooth + Kalman/Particle Filter 센서 퓨전, 아파트 환경 56대 동시 검출 실증.

Samsung Galaxy 15바이트 고정 디바이스 fingerprint 발견 — Apple보다 역설적으로 추적에 취약.

학술 paper 후보 제목: *Commodity Device as BLE Surveillance Radar — A Capability Study*

---

## 4. iOS AFU Imaging Research

**대상 환경**: iPhone 14 (iOS 26.0 ~ 26.4.2, A15 Bionic, AFU, 화면 잠금)

### 전제 조건

- iPhone이 한 번이라도 잠금 해제된 적 있는 **AFU(After First Unlock) 상태**
- 해당 Mac과 이전에 페어링된 적 있을 것 (USB 케이블 연결 시 "이 컴퓨터를 신뢰하겠습니까?" 수락 이력)
- USB 케이블
- macOS (sudo 권한)

화면 잠금 여부는 무관하다. 비밀번호는 필요하지 않다.

### 추출 가능 데이터 목록

**USB 케이블 + 페어링(기존 신뢰 관계)만으로**, 비밀번호 입력 없이, 잠금 화면 상태의 iPhone에서 다음을 추출할 수 있다.

| 대분류 | 중분류 | 내용 |
|--------|--------|------|
| **미디어** | 원본 파일 | 사진·영상 원본 전체 |
| | 썸네일 | 전체 사진 미리보기 이미지 |
| | 메타데이터 | GPS 좌표, 촬영 시각, 장소, 앨범 구성, 추억(Memories) 내역 |
| | 클라우드 연동 정보 | 연결된 Apple ID, 동기화 수량, 마지막 동기화 일시 |
| **개인 식별 정보** | 인물 데이터베이스 | 얼굴 인식 기반 인물 프로파일 및 인물별 사진 군집 |
| | 위치 이력 | 촬영 위치 기반 장소 분류 캐시, 연락처 연관 위치 캐시 |
| **AI 분석 결과** | 온디바이스 분석 DB | 얼굴 인식, 장면 분류, OCR 텍스트 추출 결과 전체 |
| | 시각 인식 인덱스 | 얼굴·사물·장면 인식 벡터 인덱스 |
| | AI 모델 파일 | 온디바이스 인식 모델 (인물, 반려동물 등) |
| **앱 및 시스템** | 앱 접근 이력 | 미디어 라이브러리에 접근한 설치 앱 목록 (50+개) |
| | 미디어 소비 이력 | 음악 라이브러리, 재생목록, 재생 횟수, 다운로드 기록 |
| **파일 시스템** | 접근 권한 | 민감 데이터 경로 전체에 대해 읽기·쓰기·삭제 완전 개방 (CRUD) |

### iOS 버전별 재현 여부

| iOS 버전 | 상태 |
|---------|------|
| iOS 26.3.1 | 취약 확인 |
| iOS 26.4.0 | 취약 확인 |
| iOS 26.4.2 (최신, 2026-04-24 기준) | **취약 확인 — 미패치** |

**제로데이 취약점 (2026-04-24 기준 iOS 26 전 사이클 미패치). Apple Bug Bounty 제출 예정.**

공격 원리, 취약점 상세, 재현 방법 등 모든 기술 세부 내용은 비공개로 유지한다.

### 다음 목표

**1. 페어링 없이 접근**

현재 달성한 추출은 사전 페어링(신뢰 관계)이 있는 Mac에서만 가능하다. 다음 단계는 페어링 이력이 전혀 없는 Mac에서도 동일한 접근을 달성하는 것이다.

Apple Bug Bounty 제출 예정으로 구체적인 접근 방향은 공개하지 않는다.

**2. 접근 경로 범위 탐색 (완료)**

민감 데이터가 집중된 특정 경로에 대해 읽기/쓰기/삭제를 포함한 완전한 CRUD 접근이 가능함을 확인했다.

**3. 역분석 심화**

확보된 iOS dyld shared cache 기반으로 관련 시스템 바이너리 역분석 진행 예정이다.

---

## 5. iOS Backup Forensic Research

**대상 환경**: iOS encrypted backup (iTunes / Finder backup) + macOS 분석 환경

본인 소유 iPhone의 암호화 백업에서 앱별 사용자 행위 흔적이 어디까지, 어떤 형태로 잔존하는지를 다회차로 검증하는 연구. 단일 앱 보안이 강해도 사용자 행위는 디바이스 전체에 분산되어 남을 수 있다는 가정 하에, 79개 앱 폴더 중 15개를 분석 완료했고 보호 모델별 9개 paradigm을 도출했다.

### 전제 조건

- 본인 소유 iPhone의 **암호화 백업** (iTunes / Finder)
- 백업 비밀번호 보유 (Manifest.db + Keybag unlock 용)
- macOS 분석 환경

### 앱별 현재 회수 가능 수준 (15 / 79)

본인 iPhone 암호화 백업을 macOS에서 분석했을 때, 각 앱에서 *지금까지 어디까지 추출이 확인되었는지* 일반 독자 기준 요약. 더 깊은 회수는 연구 중.

#### 핀테크

| 앱 | 현재 회수 가능 | 연구 중 |
|---|---|---|
| **Toss (토스)** | 전체 보유 계좌 list + 각 계좌 잔액, 카드/대출 카탈로그, 마지막 송금한 사람 계좌, 토스증권 위탁계좌 + 보유 종목 관심 list, 토스 user ID, 최근 검색어, 친구 list, 토스 알림 다수, 카드 결제 알림 (가맹점·금액·일시·끝번호), 자동이체 등록 흐름 | 송금 *받은 사람 + 금액*, 매수/매도 *수량·가격* 같은 원본 거래 timeline 본문 — 회수 시도 진행 중 |
| **KB Pay (KB국민카드)** | 사용자 실명, 보유 카드 종류, KB 그룹 16앱 ARS 정책, APNS 토큰, 가맹점 사용 location 데이터, 결제 알림 cycle | 카드 거래 원본 row (구매 상세 timeline) — 연구 중 |
| **KakaoBank (카카오뱅크)** | 앱 설치 기능 카탈로그 60+ 종, 클립보드 사용 횟수, 인앱 화면 사용 메타 | 거래 원장 / 잔액 / 송금 본문 — 연구 중 |

#### 메신저 / 메일 / 협업

| 앱 | 현재 회수 가능 | 연구 중 |
|---|---|---|
| **KakaoTalk (카카오톡)** | **대화 본문 추출 가능** — 213,901 메시지 중 90.9% 평문 복원 성공. 사용자가 가입한 모든 방, 친구 list, 닉네임 이력, 시간대별 메시지 distribution | 잔여 9.1% (특정 방 / 특정 메시지 type) — 연구 중 |
| **Microsoft Teams** | 사용자가 받은 알림 메타 (thread ID, 조직 ID, 알림 본문 글자수 까지), Microsoft 365 cross-app 흔적 (Excel 한국어 sheet 이름까지 cache), Intune MAM 등록 흔적, 1차 앱 6종 카탈로그 | 메시지 본문 자체 (알림 처리 시점 키 부재) — 연구 중 |
| **Gmail** | 사용자가 로그인한 6개 Google 계정 매핑, 18개 최근 이메일 미리보기 (제목·발신자·시각), 22명 자동완성 연락처, push 토큰 3종, Meet/Tasks/Drive 활성화 상태 | 이메일 본문 — 연구 중 |
| **Discord** | 참여한 서버 list, 친구 affinity 점수 1,242명, 음성 채널 동참자 491명, MMKV 잔존으로 키스트로크 draft 일부 복원 | 메시지 원본 본문 — 연구 중 |
| **Instagram** | DM thread 메타 (sender / timestamp / 모드), 사용자 계정 활동 흔적 | DM 본문 (iOS 백업에서 제외 처리됨) — 연구 중 |

#### AI

| 앱 | 현재 회수 가능 | 연구 중 |
|---|---|---|
| **ChatGPT** | **전부 추출 가능** — 모든 대화 본문, 대화 제목 list, 첨부 파일, 사용자 계정 매핑 4종 | (현재 회수 한계 없음) |
| **Gemini** | 사용자가 방문한 origin host 14개, 계정 매핑, 사용 흔적 메타 | 대화 본문 (디스크 미저장 schema) — 연구 중 |

#### 포털 / 이커머스 / SNS

| 앱 | 현재 회수 가능 | 연구 중 |
|---|---|---|
| **Naver (네이버)** | 검색 keyword 이력, 방문 URL 이력, 계정 정보 3축 모두 평문 회수 | 네이버 비밀 채팅 (`_cmc_secure_chat.sqlite`) — 연구 중 |
| **Coupang (쿠팡)** | 사용자 계정 JWT (memberSrl + 디바이스 모델 + 가족 2 프로필 등 전수), 검색 keyword 30건, 사용 패턴 timeline, 소스 IP, Akamai 토큰 | 주문 detail 본문, ENCRYPTED_* 자체 암호화 field — 연구 중 |
| **Everytime (에브리타임)** | 사용자 학적 메타 (school_id/campus_id/enter_year/enrollment), PostHog 큐 214건, 모션센서 fingerprint, AuthCredential 평문 | 게시글 본문 (디스크 미저장 schema) — 연구 중 |

#### 본인인증 / 가상자산

| 앱 | 현재 회수 가능 | 연구 중 |
|---|---|---|
| **KTAuth (KT PASS)** | 디바이스 식별자 3종, 등록된 인증 방식 2가지 (Face ID + PIN, FIDO AAID 포함), 사용 timeline (Adobe Lifecycle), 13개 KT 서비스 catalog | 핵심 본인인증 PII (실명·생년월일·CI/DI) — 자체 암호화로 보호, 연구 중 |
| **Upbit (업비트)** | 사용자 모드 (게스트 vs 로그인), Apple App Attest 인증서 (iOS 버전 + Team ID), 위젯 BTC fetch 9회 흔적 | 거래 history / 자산 본문 — 연구 중 |

64개 추가 앱 분석 진행 중 — 한국 사용자 일상 앱 풀 (모빌리티 / 숙박 / 미디어 / 생산성 / 추가 핀테크 / 추가 메신저 등).

### iOS 버전별 재현 여부

| iOS 버전 | 상태 |
|---|---|
| iOS 18.x 백업 | 검증 |
| iOS 26.x 백업 | 검증 — 진행 중 |

### 다음 목표

- 미분석 앱 64개 추가 (한국 사용자 일상 앱 풀 — 모빌리티 / 숙박 / 미디어 / 생산성 / 추가 핀테크)
- 다회차 분석을 통한 cross-domain pivoting 확장 (단일 앱 도메인이 보호되어도 시스템 도메인 + 다른 앱 백업에서 동일 사용자 활동 재구성)
- 앱별 보호 paradigm 매트릭스 갱신 + 신규 paradigm 후보 식별
- 반복 사용 분석 패턴의 도구화

분석 알고리즘, 추출 스크립트, 사용자 데이터 샘플, 보고서 본문 등 기술 세부는 비공개로 유지한다.

---

## Upcoming Research

- 금융권 아티팩트: 은행 웹뱅킹/앱 사용 흔적, 인터넷뱅킹 세션 데이터
- 블록체인/암호화폐 지갑: MetaMask, Phantom 등 브라우저 확장 지갑의 로컬 키스토어, 시드 구문 잔존 여부
- 공공기관 아티팩트: 정부24, 홈택스, 전자민원 브라우저 아티팩트

---

## Non-Public

다음은 공개하지 않는다.

- 분석/추출 스크립트 소스 코드
- 추출된 데이터 샘플
- 증거 파일 (DB 복사본, 캐시 등)
- 상세 기술 문서 (바이너리 포맷, 파싱 알고리즘, 복원 절차)
- 취약점 상세 (공격 경로, 취약 서비스명, exploit 코드)
- 실행 로그
- 사용자 식별 가능 정보

---

## Disclaimer

본 연구는 두 축으로 구성된다.

- **Defensive Security (Digital Forensics)** — 개인 연구 및 소속 기업의 보안 솔루션 삽입을 목적으로 진행.
- **Offensive Security** — 개인 연구 목적이며, 악용 우려로 인해 상세 기법은 공개하지 않는다.

모든 연구는 인가된 시스템에서의 보안 연구 및 디지털 포렌식 교육 범위 내에서 수행되며, 비인가 시스템에 대한 사용은 관련 법률에 의해 금지된다.

---

## License

[GNU General Public License v3.0](LICENSE)

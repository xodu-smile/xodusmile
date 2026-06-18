<#
.SYNOPSIS
  GitHub 최종 푸시 정리 스크립트 (RansomGuard EDR)

.DESCRIPTION
  git 바이너리가 정상 복구된 뒤 실행하세요.
  1) git 동작 확인
  2) .gitignore 에 걸리지만 과거에 이미 추적(커밋)된 파일을 찾아 git rm --cached 로 추적 해제
     (예: 과거에 잘못 올라간 .venv/, minifilter/packages/, reports/, *.db 등)
  3) 변경 사항을 스테이징 → 상태 요약 출력
  4) -DryRun 이 아니면 commit & push (origin/develop_1)

.PARAMETER DryRun
  실제 commit/push 없이 무엇이 정리·스테이징될지 미리보기만 한다.

.PARAMETER Message
  커밋 메시지. 미지정 시 기본값 사용.

.EXAMPLE
  pwsh -File scripts\finalize_push.ps1 -DryRun     # 미리보기
  pwsh -File scripts\finalize_push.ps1             # 실제 정리+커밋+푸시
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$Message = "chore: 리포 정리 — 추적된 무시대상 제거, .gitignore 보강",
    [string]$Branch  = "develop_1"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)   # 리포 루트로 이동

Write-Host "== 0. git 동작 확인 ==" -ForegroundColor Cyan
try {
    $ver = (git --version) 2>$null
    if (-not $ver) { throw "git --version 결과 없음" }
    Write-Host "  $ver"
} catch {
    Write-Error "git 이 실행되지 않습니다. Git for Windows(ARM64) 재설치/복구 후 다시 실행하세요. ($($_.Exception.Message))"
    exit 1
}

Write-Host "`n== 1. 현재 브랜치 / 상태 ==" -ForegroundColor Cyan
git rev-parse --abbrev-ref HEAD
git status --short

Write-Host "`n== 2. 추적 중이지만 .gitignore 에 걸리는 파일 (정리 대상) ==" -ForegroundColor Cyan
# -c: cached(추적됨), -i: ignored, --exclude-standard: .gitignore 규칙 적용
$tracked_ignored = git ls-files -ci --exclude-standard
if ($tracked_ignored) {
    $tracked_ignored | ForEach-Object { Write-Host "  rm --cached: $_" -ForegroundColor Yellow }
    if (-not $DryRun) {
        # 작업 트리 파일은 보존하고 인덱스에서만 제거
        $tracked_ignored | ForEach-Object { git rm -r --cached --quiet -- "$_" }
        Write-Host "  → 인덱스에서 추적 해제 완료 (디스크 파일은 유지)" -ForegroundColor Green
    } else {
        Write-Host "  (DryRun: 실제 제거 안 함)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  없음 — 추적 상태 깨끗함 ✓" -ForegroundColor Green
}

Write-Host "`n== 3. 스테이징 ==" -ForegroundColor Cyan
if (-not $DryRun) { git add -A }
git status --short

if ($DryRun) {
    Write-Host "`n[DryRun] 여기까지가 미리보기입니다. 실제 커밋/푸시는 -DryRun 없이 다시 실행하세요." -ForegroundColor Magenta
    exit 0
}

Write-Host "`n== 4. 커밋 & 푸시 ($Branch) ==" -ForegroundColor Cyan
# 변경 사항이 없으면 커밋 스킵
$pending = git status --porcelain
if ($pending) {
    git commit -m $Message
} else {
    Write-Host "  커밋할 변경 없음 — 커밋 스킵" -ForegroundColor DarkGray
}
git push origin $Branch
Write-Host "`n완료: origin/$Branch 로 푸시했습니다." -ForegroundColor Green

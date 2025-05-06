#!/usr/bin/bash


# 개별 점검 함수 정의
check_account() {
echo
echo
echo " █ U 01 █ root 계정 원격접속 제한"
sleep 1

sshd_config="/etc/ssh/sshd_config"
permit_root_login=$(grep -i "^PermitRootLogin" $sshd_config | awk '{print $2}')
if [[ "$permit_root_login" == "no" ]]; then
    echo "root 계정의 원격 접속이 차단되어 있습니다."
    echo "허용을 원하시면 /etc/ssh/sshd_config 파일에서 PermitRootLogin 을 yes로
 수정하십시오."
else
    echo "root 계정의 원격 접속이 허용되어 있습니다."
    echo "차단을 원하시면 /etc/ssh/sshd_config 파일에서 PermitRootLogin 을 no로 수정하십시오."
fi


echo
echo
echo " █ U 02 █ 패스워드 복잡성 설정"
sleep 1
pam_config2="/etc/pam.d/system-auth"
login_defs2="/etc/login.defs"

check_password_complexity() {
        echo "패스워드 복잡성 설정 점검 결과 :"
if grep -q "pam_pwquality.so" $pam_config2 || grep -q "pam_cracklib.so" $pam_config2;
then
        echo "패스워드 복잡성 정책이 적용되어 있습니다."
        echo "정책 수정을 원하시면 ${pam_config2} 파일과 ${login_defs2} 파일을 >정책에 맞게 수정하십시오."
else
        echo "패스워드 복잡성 정책이 적용되어 있지 않습니다."
        echo "${login_defs2} 를  수정하여 8자 이상의 영문, 숫자, 특수문자 조합으
로 암호 설정 및 패스워드 복잡성 옵션을 설정하십시오. "
fi
}
check_password_complexity

echo
echo
echo " █ U 03 █ 계정 잠금 임계값 설정"
sleep 1
pam_config3="/etc/pam.d/system-auth"
pam_password_config3="/etc/pam.d/password-auth"

check_account_lock_threshold() {
    echo "계정 잠금 임계값 설정 점검 결과 :"
    if grep -q "pam_tally2.so" $pam_config3 || grep -q "pam_faillock.so" $pam_config3; then
        echo "로그인 실패 시 계정 잠금 설정이 적용되어 있습니다. (/etc/pam.d/system-auth)"
    else
        echo "로그인 실패 시 계정 잠금 설정이 적용되어 있지 않습니다. (/etc/pam.d/system-auth)"
        echo "설정을 변경하려면 /etc/pam.d/system-auth 파일을 정책에 맞게  수정하십시오."
    fi

    if grep -q "pam_tally2.so" $pam_password_config3 || grep -q "pam_faillock.so" $pam_password_config3; then
        echo "로그인 실패 시 계정 잠금 설정이 적용되어 있습니다. (/etc/pam.d/password-auth)"
    else
        echo "로그인 실패 시 계정 잠금 설정이 적용되어 있지 않습니다. (/etc/pam.d/password-auth)"
        echo "설정을 변경하려면 /etc/pam.d/password-auth 파일을 정책에 맞게  수정하십시오."
    fi
    echo
    echo "로그인 실패 임계값 설정 :"
    if [ -f /etc/security/faillock.conf ]; then
        if grep -q "deny=" /etc/security/faillock.conf; then
            deny_threshold=$(grep "deny=" /etc/security/faillock.conf | awk -F '=' '{print $2}')
            echo "로그인 실패 임계값 : $deny_threshold"
        else
            echo "로그인 실패 임계값 설정이 적용되어 있지 않습니다."
            echo "설정을 변경하려면 /etc/security/faillock.conf 파일을 정책에 맞
게 수정하십시오."
        fi
    else
        echo "/etc/security/faillock.conf 파일이 존재하지 않습니다."
    fi
}

check_account_lock_threshold


echo
echo
echo " █ U 04 █ 패스워드 파일 보호"
sleep 1
check_password_encryption() {
  echo "/etc/passwd와 /etc/shadow에서 암호화 설정 확인 결과 :"

  while IFS=: read -r username password _; do
    if [[ "$username" == "root" || "$username" == "en" ]]; then
      shadow_entry=$(grep "^$username:" /etc/shadow)

      if [[ "$password" == "x" ]]; then
          if [[ -z "$shadow_entry" || "$(echo $shadow_entry | cut -d: -f2)" == "" ]]; then
          echo "경고: 사용자 '$username'는 /etc/passwd에 암호화가 되어 있지만 /etc/shadow에 암호화된 비밀번호가 없습니다."
        else
          echo "사용자 '$username'는 /etc/shadow에 암호화가 되어 있습니다."
        fi
      else
        echo "경고: 사용자 '$username'는 /etc/passwd에 암호화가 되어 있지 않습니
다."
        echo "패스워드 정책을 설정하여 적용하십시오."
      fi
    fi
  done < /etc/passwd
}

check_password_encryption


echo
echo
echo " █ U 44 █ 사용자 계정 정보에서 root(UID=0) 계정과 동일한 UID를 가진 계정이 존재하는지 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# UID 점검 함수
check_root_uid() {
    echo "🔍 /etc/passwd 파일에서 UID=0인 계정을 점검 중..."

    # /etc/passwd 파일에서 UID=0인 계정 검색
    UIDS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)

    if [ -z "$UIDS" ]; then
        echo "✅ UID=0인 계정은 존재하지 않습니다."
    else
        echo "⚠️ UID=0인 계정이 다음과 같이 존재합니다: "
        echo "$UIDS"
        echo "🔧 해결 방법:"
        echo "1. 위의 계정들이 root와 동일한 UID(0)를 가진 계정입니다."
        echo "2. 해당 계정들이 root 계정 외에 시스템에서 사용되는 계정이라면, UID를 변경해야 합니다."
        echo "3. 불필요한 계정이라면 삭제할 수 있습니다."
        echo "4. 계정이 사용 중인 경우에는 명령어로 변경할 수 없으며, /etc/passwd 파일에서 수동으로 수정해야 합니다."
    fi

    echo "=============================================="
}

# 점검 함수 실행
check_root_uid


echo
echo
echo " █ U 45 █ su 명령어 사용을 허용하는 사용자를 지정한 그룹이 설정되어 있는지 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# su 명령어 그룹 점검 함수
check_su_group() {
    echo "🔍 su 명령어 사용을 허용하는 그룹 설정 점검 중..."

    # /etc/pam.d/su 파일에서 su 명령어 허용 그룹 확인
    if grep -q "auth required pam_wheel.so" /etc/pam.d/su; then
        echo "✅ su 명령어 사용을 허용하는 그룹 설정이 PAM을 통해 적용되어 있습니다."
    else
        echo "⚠️ su 명령어 사용을 허용하는 그룹 설정이 되어 있지 않습니다."
        echo "🔧 해결 방법:"
        echo "1. su 명령어 사용을 허용하는 그룹을 설정하려면 PAM 설정을 수정해야 합니다."
        echo "2. /etc/pam.d/su 파일에 다음 라인을 추가합니다: auth required pam_wheel.so"
    fi

    # /etc/group 파일에서 wheel 그룹 존재 여부 점검
    if grep -q "^wheel:" /etc/group; then
        echo "✅ wheel 그룹이 존재합니다."
    else
        echo "⚠️ wheel 그룹이 존재하지 않습니다. wheel 그룹을 생성해야 합니다."
        echo "🔧 해결 방법:"
        echo "1. wheel 그룹을 생성합니다: sudo groupadd wheel"
        echo "2. su 명령어를 사용할 계정을 wheel 그룹에 추가합니다: sudo usermod -aG wheel <사용자>"
    fi

    # su 명령어의 권한 점검
    SU_PERMISSION=$(stat -c %a /bin/su)
    if [ "$SU_PERMISSION" == "4750" ]; then
        echo "✅ su 명령어의 권한이 올바르게 설정되어 있습니다 (4750)."
    else
        echo "⚠️ su 명령어의 권한이 올바르지 않습니다. 권한을 4750으로 설정해야 합니다."
        echo "🔧 해결 방법:"
        echo "1. su 명령어의 권한을 4750으로 변경합니다: sudo chmod 4750 /bin/su"
    fi

    echo "=============================================="
}

# 점검 함수 실행
check_su_group



echo
echo
echo " █ U 46 █ 시스템 정책에 패스워드 최소 길이 설정이 적용되어 있는지 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# 패스워드 최소 길이 점검 함수
check_password_length() {
    echo "🔍 /etc/login.defs 파일에서 패스워드 최소 길이를 점검 중..."

    # /etc/login.defs 파일에서 PASS_MIN_LEN 값을 확인 (주석 제외, 정확한 값을 찾기)
    MIN_LEN=$(grep -E "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}' | tr -d '[:space:]')

    # 값이 비어 있는 경우 기본 값(0) 설정
    if [[ -z "$MIN_LEN" ]]; then
        echo "⚠️  PASS_MIN_LEN 설정을 찾을 수 없습니다. 파일을 확인해주세요."
        echo "🔧 해결 방법:"
        echo "1. /etc/login.defs 파일을 열어 PASS_MIN_LEN 값이 숫자로 설정되어 있는지 확인하세요."
        echo "2. 패스워드 최소 길이를 8자 이상으로 설정하려면 'PASS_MIN_LEN 8'로 변경하세요."
        return
    fi

    # 정수 비교를 위해 값이 숫자인지 확인
    if ! [[ "$MIN_LEN" =~ ^[0-9]+$ ]]; then
        echo "⚠️  PASS_MIN_LEN 값이 올바르지 않습니다. 현재 설정: $MIN_LEN"
        echo "🔧 해결 방법:"
        echo "1. /etc/login.defs 파일을 열어 PASS_MIN_LEN 값이 숫자로 설정되어 있는지 확인하세요."
        echo "2. 패스워드 최소 길이를 8자 이상으로 설정하려면 'PASS_MIN_LEN 8'로 변경하세요."
        return
    fi

    # 패스워드 길이 기준 비교
    if [[ "$MIN_LEN" -ge 8 ]]; then
        echo "✅ 패스워드 최소 길이가 8자 이상으로 설정되어 있습니다. (현재 설정: $MIN_LEN)"
    else
        echo "⚠️  패스워드 최소 길이가 8자 미만입니다. 현재 설정: $MIN_LEN"
        echo "🔧 해결 방법:"
        echo "1. 패스워드 최소 길이를 8자 이상으로 설정하려면 /etc/login.defs 파일을 수정해야 합니다."
        echo "2. PASS_MIN_LEN 값을 8로 변경하세요."
    fi

    echo "=============================================="
}

# 점검 함수 실행
check_password_length


echo
echo
echo " █ U 47 █ 시스템 정책에 패스워드 최대 사용 기간(90일 이하) 설정 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# 패스워드 최대 사용 기간 점검 함수
check_password_max_days() {
    echo "🔍 /etc/login.defs 파일에서 패스워드 최대 사용 기간을 점검 중..."

    # /etc/login.defs 파일에서 PASS_MAX_DAYS 값을 확인 (주석 제외, 정확한 값을 찾기)
    MAX_DAYS=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}' | tr -d '[:space:]')

    # 값이 비어 있는 경우 기본 값(0) 설정
    if [[ -z "$MAX_DAYS" ]]; then
        echo "⚠️  PASS_MAX_DAYS 설정을 찾을 수 없습니다. 파일을 확인해주세요."
        return
    fi

    # 정수 비교를 위해 값이 숫자인지 확인
    if ! [[ "$MAX_DAYS" =~ ^[0-9]+$ ]]; then
        echo "⚠️  PASS_MAX_DAYS 값이 올바르지 않습니다. 현재 설정: $MAX_DAYS"
        echo "🔧 해결 방법:"
        echo "1. /etc/login.defs 파일을 열어 PASS_MAX_DAYS 값이 숫자로 설정되어 있는지 확인하세요."
        echo "2. 패스워드 최대 사용 기간을 90일 이하로 설정하려면 'PASS_MAX_DAYS 90'로 변경하세요."
        return
    fi

    # 패스워드 최대 사용 기간 점검
    if [[ "$MAX_DAYS" -le 90 ]]; then
        echo "✅ 패스워드 최대 사용 기간이 90일 이하로 설정되어 있습니다. (현재 설정: $MAX_DAYS 일)"
    else
        echo "⚠️  패스워드 최대 사용 기간이 90일 초과입니다. 현재 설정: $MAX_DAYS 일"
        echo "🔧 해결 방법:"
        echo "1. 패스워드 최대 사용 기간을 90일 이하로 설정하려면 /etc/login.defs 파일을 수정해야 합니다."
        echo "2. PASS_MAX_DAYS 값을 90 이하로 변경하세요."
        echo "3. 다음 명령어로 설정을 변경할 수 있습니다: sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs"
    fi

    echo "=============================================="
}

# 점검 함수 실행
check_password_max_days


echo
echo
echo " █ U 48 █ 시스템 정책에 패스워드 최소 사용 기간 설정 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# 패스워드 최소 사용 기간 점검 함수
check_password_min_days() {
    echo "🔍 /etc/login.defs 파일에서 패스워드 최소 사용 기간을 점검 중..."

    # /etc/login.defs 파일에서 PASS_MIN_DAYS 값을 확인 (주석 제외, 정확한 값을 찾기)
    MIN_DAYS=$(grep -E "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}' | tr -d '[:space:]')

    # 값이 비어 있는 경우 기본 값(0) 설정
    if [[ -z "$MIN_DAYS" ]]; then
        echo "⚠️  PASS_MIN_DAYS 설정을 찾을 수 없습니다. 파일을 확인해주세요."
        return
    fi

    # 정수 비교를 위해 값이 숫자인지 확인
    if ! [[ "$MIN_DAYS" =~ ^[0-9]+$ ]]; then
        echo "⚠️  PASS_MIN_DAYS 값이 올바르지 않습니다. 현재 설정: $MIN_DAYS"
        echo "🔧 해결 방법:"
        echo "1. /etc/login.defs 파일을 열어 PASS_MIN_DAYS 값이 숫자로 설정되어 있는지 확인하세요."
        echo "2. 패스워드 최소 사용 기간을 1일 이상으로 설정하려면 'PASS_MIN_DAYS 1'로 변경하세요."
        return
    fi

    # 패스워드 최소 사용 기간 점검
    if [[ "$MIN_DAYS" -ge 1 ]]; then
        echo "✅ 패스워드 최소 사용 기간이 1일 이상으로 설정되어 있습니다. (현재 설정: $MIN_DAYS 일)"
    else
        echo "⚠️  패스워드 최소 사용 기간이 1일 미만입니다. 현재 설정: $MIN_DAYS 일"
        echo "🔧 해결 방법:"
        echo "1. 패스워드 최소 사용 기간을 1일 이상으로 설정하려면 /etc/login.defs 파일을 수정해야 합니다."
        echo "2. PASS_MIN_DAYS 값을 1 이상으로 변경하세요."
        echo "3. 다음 명령어로 설정을 변경할 수 있습니다: sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs"
    fi

    echo "=============================================="
}

# 점검 함수 실행
check_password_min_days


echo
echo
echo " █ U 49 █ 불필요한 계정 제거 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

unused_accounts=$(cat /etc/passwd | egrep "lp|uucp|nuucp")
if [ -z "$unused_accounts" ]; then
    echo "양호: 불필요한 계정이 없습니다."
else
    echo "취약: 불필요한 계정 발견!"
    echo "$unused_accounts"
    echo "🛠️  해결 방안: userdel <계정명>으로 불필요한 계정 삭제"
fi


echo
echo
echo " █ U 50 █ 관리자 그룹 최소 계정 포함 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

root_group=$(cat /etc/group | grep '^root:' | awk -F: '{print $4}')
if [ "$root_group" == "root" ]; then
    echo "양호: 관리자 그룹에 root 계정만 포함됨"
else
    echo "취약: root 그룹에 불필요한 계정 포함!"
    echo "$root_group"
    echo "🛠️  해결 방안: vi /etc/group 편집 후 불필요한 계정 삭제"
fi


echo
echo
echo " █ U 51 █ 계정 없는 그룹 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

empty_groups=$(awk -F: '{print $1}' /etc/group | while read group; do
    if ! grep -q ":$group:" /etc/passwd; then
        echo "$group"
    fi
done)
if [ -z "$empty_groups" ]; then
    echo "양호: 계정 없는 그룹이 없습니다."
else
    echo "취약: 계정 없는 그룹 발견!"
    echo "$empty_groups"
    echo "🛠️  해결 방안: groupdel <그룹명>으로 불필요한 그룹 삭제"
fi


echo
echo
echo " █ U 52 █ 불필요한 계정 제거 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

echo "[U-52] 동일한 UID 점검"
duplicate_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
if [ -z "$duplicate_uids" ]; then
    echo "양호: 중복된 UID가 없습니다."
else
    echo "취약: 중복된 UID 발견!"
    echo "$duplicate_uids"
    echo "🛠️  해결 방안: usermod -u <새 UID> <계정명> 으로 UID 변경"
fi


echo
echo
echo " █ U 53 █ 불필요한 계정 쉘 설정 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

unnecessary_shells=$(cat /etc/passwd | grep -E "^daemon|^bin|^sys|^adm|^listen|^nobody|^operator" | grep -v "nologin")
if [ -z "$unnecessary_shells" ]; then
    echo "양호: 불필요한 계정 쉘이 /bin/false 또는 nologin으로 설정됨"
else
    echo "취약: 불필요한 계정에 쉘이 부여됨!"
    echo "$unnecessary_shells"
    echo "🛠️  해결 방안: usermod -s /sbin/nologin <계정명>으로 쉘 변경"
fi


echo
echo
echo " █ U 54 █ Session Timeout 설정 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

timeout=$(grep -E "TMOUT" /etc/profile 2>/dev/null)
if echo "$timeout" | grep -q "TMOUT=600"; then
    echo "양호: Session Timeout이 600초(10분) 이하로 설정됨"
else
    echo "취약: Session Timeout이 설정되지 않음!"
    echo "🛠️  해결 방안: /etc/profile 에 TMOUT=600 추가"
fi


    echo
    echo  
    echo "✅ 계정관리 점검완료"
    echo
    read -p "🔄 엔터 키를 눌러 계속..."
}

check_file_dir() {



echo
echo
echo " █ U 05 █ root홈, 패스 디렉터리 권한 및 패스 설정"
sleep 1
ROOT_PATH=$(sudo -u root echo $PATH)

if [[ "$ROOT_PATH" =~ (^\.|:.*\.:.*) ]]; then
  echo "root계정의 PATH 환경변수에 취약점이 있습니다."
  echo "환경변수 설정 파일("/.profile", "/.cshrc" 등)과 "/etc/profile"등
에서 "."을 환경변수의 마지막으로 이동시키십시오."
else
  echo "root계정의 PATH 환경변수의 설정이 양호합니다."
fi




echo
echo
echo " █ U 06 █ 파일 및 디렉터리 소유자 설정"
sleep 1
CHECK_DIR="/"

if find "$CHECK_DIR" \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2>/dev/null | grep -q .; then
  echo "소유자가 불분명한 파일이나 디렉터리가 존재합니다."
  echo "파일 및 디렉터리를 삭제 또는 소유자를 변겅하십시오."
else
  echo "소유자가 불분명한 파일이나 디렉터리가 없습니다."
fi






echo
echo
echo " █ U 07 █ /etc/passwd 파일 소유자 및 권한 설정"
sleep 1
FILE="/etc/passwd"

FILE_INFO=$(ls -l $FILE)

FILE_PERMISSION=$(echo "$FILE_INFO" | awk '{print $1}')
FILE_OWNER=$(echo "$FILE_INFO" | awk '{print $3}')

if [[ "$FILE_OWNER" == "root" && "$FILE_PERMISSION" == "rw-r--r--" ]]; then
  echo "/etc/passwd 파일 소유자 및 권한은 root로 양호합니다."
else
  echo "/etc/passwd 파일 소유자 및 권한에 문제가 있습니다."
  echo "권한을 변경하여 주십시오. (소유자 root, 권한 644)"
fi




echo
echo
echo " █ U 08 █ /etc/shadow 파일 소유자 및 권한 설정"
sleep 1
FILE="/etc/shadow"

FILE_INFO=$(ls -l $FILE)

FILE_PERMISSION=$(echo "$FILE_INFO" | awk '{print $1}')
FILE_OWNER=$(echo "$FILE_INFO" | awk '{print $3}')

if [[ "$FILE_OWNER" == "root" && "$FILE_PERMISSION" == "r--------" ]]; then
  echo "/etc/shadow 파일 소유자 및 권한은 root로 양호합니다."
else
  echo "/etc/shadow 파일 소유자 및 권한에 문제가 있습니다."
  echo "권한을 변경하여 주십시오. (소유자 root, 권한 400)"
fi







echo
echo
echo " █ U 09 █ /etc/hosts 파일 소유자 및 권한 설정"
sleep 1
FILE="/etc/hosts"
OWNER=$(stat -c "%U" $FILE)
PERM=$(stat -c "%a" $FILE)

if [[ "$OWNER" == "root" && "$PERM" -le 600 ]]; then
    echo "/etc/hosts의 소유자 및 권한이 양호합니다."
else
    echo "/etc/hosts의 소유자 및 권한에 문제가 있습니다."
    echo "권한을 변경하여 주십시오. (소유자: root, 권한: 600)"
fi





echo
echo
echo " █ U 10 █ /etc/(x)inetd.conf 파일 소유자 및 권한 설정"
sleep 1
FILE="/etc/inetd.conf"
OWNER=$(stat -c "%U" $FILE 2>/dev/null)
PERM=$(stat -c "%a" $FILE 2>/dev/null)

if [[ "$OWNER" == "root" && "$PERM" -eq 600 ]]; then
    echo "/etc/inetd.conf의 소유자 및 권한이 양호합니다."
else
    echo "/etc/inetd.conf의 소유자 및 권한에 문제가 있습니다."
    echo "권한을 변경하여 주십시오. (소유자: root, 권한: 600)"
fi





echo
echo
echo " █ U 11 █ /etc/syslog.conf 파일 소유자 및 권한 설정"
sleep 1
FILE="/etc/syslog.conf"
OWNER11=$(stat -c "%U" $FILE 2>/dev/null)
PERM11=$(stat -c "%a" $FILE 2>/dev/null)

if [[ "$OWNER11" == "root" || "$OWNER11" == "bin" || "$OWNER11" == "sys" ]] && [[ "$PERM11" -le 640 ]]; then
    echo "/etc/syslog.conf의 소유자 및 권한이 양호합니다."
else
    echo "/etc/syslog.conf의 소유자 및 권한에 문제가 있습니다."
    echo "권한을 변경하여 주십시오. (소유자: root(또는 bin, sys), 권한: 640 이하)"
fi






echo
echo
echo " █ U 12 █ /etc/services 파일 소유자 및 권한 설정"
sleep 1
FILE="/etc/services"
OWNER12=$(stat -c "%U" $FILE 2>/dev/null)
PERM12=$(stat -c "%a" $FILE 2>/dev/null)

if [[ "$OWNER12" == "root" || "$OWNER12" == "bin" || "$OWNER12" == "sys" ]] && [[ "$PERM12" -le 644 ]]; then
    echo "/etc/services의 소유자 및 권한이 양호합니다."
else
    echo "/etc/services의 소유자 및 권한에 문제가 있습니다."
    echo "권한을 변경하여 주십시오. (소유자: root(또는 bin, sys), 권한: 644 이하)"
fi






echo
echo
echo " █ U 13 █ SUID, SGID, 설정 파일점검"
sleep 1
CHECK_FILES13=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

if [[ -z "$CHECK_FILES13" ]]; then
    echo "주요 실행파일의 권한에 SUID, SGID 설정이 부여되어 있지 않습니다. (양호
)"
else
    echo "주요 실행파일의 권한에 SUID, SGID 설정이 부여되어 있습니다."
    echo "불필요한 SUID, SGID 파일을 제거하고 의심스럽거나 특이한 파일의 SUID를 제거하십시오."

fi




echo
echo
echo " █ U 14 █ 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
sleep 1
ENV_FILES14=(".profile" ".kshrc" ".cshrc" ".bashrc" ".bash_profile" ".login" ".exrc" ".netrc")

PROBLEM_FOUND14=0

for HOME_DIR14 in $(awk -F: '{ if ($6 ~ /^\//) print $6 }' /etc/passwd); do
    USER_NAME14=$(basename "$HOME_DIR14")

    for FILE14 in "${ENV_FILES14[@]}"; do
        ENV_FILE_PATH14="$HOME_DIR14/$FILE14"

        if [ -f "$ENV_FILE_PATH14" ]; then
            FILE_OWNER14=$(stat -c "%U" "$ENV_FILE_PATH14")
            FILE_PERM14=$(stat -c "%a" "$ENV_FILE_PATH14")

            if [[ "$FILE_OWNER14" != "root" && "$FILE_OWNER14" != "$USER_NAME14" ]] || [[ "$FILE_PERM14" -gt 644 ]]; then
                PROBLEM_FOUND14=1
                break 2
            fi
        fi
    done
done

if [[ "$PROBLEM_FOUND14" -eq 1 ]]; then
    echo "환경변수 파일에 대한 소유자 및 접근권한에 문제가 있습니다."
    echo "chown, chmod 명령어를 사용하여 소유자와 권한을 변경하십시오."
else
    echo "환경변수 파일에 대한 소유자 및 접근권한이 양호합니다."
fi






echo
echo
echo " █ U 15 █ world writable 파일 점검"
sleep 1
WW_FILES15=$(find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null)

if [[ -z "$WW_FILES15" ]]; then
    echo "불필요한 world writable 파일이 존재하지 않습니다."
else
    echo "불필요한 world writable 파일이 존재합니다."
    echo "사용 목적을 확인하고 불필요시 삭제하십시오."
fi






echo
echo
echo " █ U 16 █ /dev에 존재하지 않는 device 파일 점검"
sleep 1
DEV_FILES16=$(find /dev -type f -exec ls -l {} \; 2>/dev/null)

if [[ -z "$DEV_FILES16" ]]; then
    echo "/dev에 대한 파일 점검 결과 존재하지 않은 device 파일을 제거하였거나 양호한 상태입니다."
else
    echo "/dev에 대한 파일 점검이 되지 않았거나, 존재하지 않은 device 파일이 존재합니
다."
    echo "불필요한 파일을 삭제하십시오."
fi




echo
echo
echo " █ U 17 █ $HOME/.rhosts, hosts.equiv 사용 금지"
sleep 1
if [ -f /etc/hosts.equiv ]; then
    OWNER17=$(stat -c "%U" /etc/hosts.equiv)
    PERM17=$(stat -c "%a" /etc/hosts.equiv)
    PLUS_CHECK17=$(grep -q '^\s*\+' /etc/hosts.equiv && echo "FOUND")

    echo "ls -al /etc/hosts.equiv"
    
    if [[ "$OWNER17" != "root" ]] || [[ "$PERM17" -gt 600 ]] || [[ "$PLUS_CHECK17" == "FOUND" ]]; then
        PROBLEM_FOUND17=1
    fi
fi

for HOME_DIR17 in $(awk -F: '{ if ($6 ~ /^\//) print $6 }' /etc/passwd); do
    RHOSTS_FILE17="$HOME_DIR17/.rhosts"
    
    if [ -f "$RHOSTS_FILE17" ]; then
        OWNER17=$(stat -c "%U" "$RHOSTS_FILE17")
        PERM17=$(stat -c "%a" "$RHOSTS_FILE17")
        PLUS_CHECK17=$(grep -q '^\s*\+' "$RHOSTS_FILE17" && echo "FOUND")

        echo "ls -al $RHOSTS_FILE17"
        
        if [[ "$OWNER17" != "root" && "$OWNER17" != "$(basename "$HOME_DIR17")" ]] || [[ "$PERM17" -gt 600 ]] || [[ "$PLUS_CHECK17" == "FOUND" ]]; then
            PROBLEM_FOUND17=1
        fi
    fi
done

if [[ "$PROBLEM_FOUND17" -eq 1 ]]; then
    echo "파일 설정에 문제가 있습니다."
    echo "모든 호스트 허용이 포함되어 있다거나 파일 권한이 600 이하인 경우 설정을 변경하십시오."
else
    echo "파일에 모든 호스트 허용이 되어있지 않습니다. (양호)"
fi






echo
echo
echo " █ U 18 █ 접속 IP 및 포트 제한"
sleep 1
PROBLEM_FOUND18=1

if [ -f /etc/hosts.deny ] && grep -q -v "^#" /etc/hosts.deny; then
    PROBLEM_FOUND18=0
fi

if [ -f /etc/hosts.allow ] && grep -q -v "^#" /etc/hosts.allow; then
    PROBLEM_FOUND18=0
fi

if command -v iptables &>/dev/null; then
    if iptables -L | grep -q "ACCEPT"; then
        PROBLEM_FOUND18=0
    fi
fi

if [ -f /etc/ipf/ipf.conf ] && grep -q -v "^#" /etc/ipf/ipf.conf; then
    PROBLEM_FOUND18=0
fi

if command -v inetadm &>/dev/null; then
    if inetadm -p | grep -q "tcp_wrappers=true"; then
        PROBLEM_FOUND18=0
    fi
fi

if [[ "$PROBLEM_FOUND18" -eq 0 ]]; then
    echo "IP 주소 및 포트 제한이 설정되어 있습니다. (양호)"
else
    echo "IP 주소 및 포트 제한이 설정되어 있지 않습니다."
    echo "제한 애플리케이션 정책을 변경하십시오."
fi






echo
echo
echo " █ U 55 █ hosts.lpd 파일 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

if [ ! -f /etc/hosts.lpd ]; then
    echo "양호: hosts.lpd 파일이 존재하지 않음"
else
    perm=$(stat -c %a /etc/hosts.lpd)
    owner=$(stat -c %U /etc/hosts.lpd)
    if [ "$owner" == "root" ] && [ "$perm" -eq 600 ]; then
        echo "양호: hosts.lpd 파일의 권한과 소유자 설정 양호"
    else
        echo "취약: hosts.lpd 파일 설정 오류!"
        echo "🛠️  해결 방안: chmod 600 /etc/hosts.lpd && chown root /etc/hosts.lpd"
    fi
fi






echo
echo
echo " █ U 56 █ UMASK 설정 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

umask_value=$(umask)
if [ "$umask_value" -le 022 ]; then
    echo "양호: UMASK가 022 이하로 설정됨"
else
    echo "취약: UMASK 값이 과도하게 설정됨!"
    echo "🛠️  해결 방안: /etc/profile 파일에 umask 022 추가"
fi







echo
echo
echo " █ U 57 █ 홈 디렉터리 권한 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

awk -F: '{ print $1, $6 }' /etc/passwd | while read user home; do
    if [ -d "$home" ]; then
        perm=$(stat -c "%U %A" "$home")
        if [[ "$perm" =~ "root" && "$perm" =~ "drwx------" ]]; then
            echo "양호: $user 홈 디렉터리 권한 양호"
        else
            echo "취약: $user 홈 디렉터리 권한 미흡"
            echo "🛠️  해결 방안: chown $user $home && chmod 700 $home"
        fi
    fi
done







echo
echo
echo " █ U 58 █ 홈 디렉터리 존재 여부 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

awk -F: '{ print $1, $6 }' /etc/passwd | while read user home; do
    if [ ! -d "$home" ]; then
        echo "취약: $user의 홈 디렉터리($home)가 존재하지 않음!"
        echo "🛠️  해결 방안: userdel $user 또는 mkdir $home"
    fi
done







echo
echo
echo " █ U 59 █ 숨겨진 파일 및 디렉터리 검색 및 제거 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

HIDDEN_FILES=$(find / -type f -name ".*" 2>/dev/null)
HIDDEN_DIRS=$(find / -type d -name ".*" 2>/dev/null)
if [ -z "$HIDDEN_FILES" ] && [ -z "$HIDDEN_DIRS" ]; then
  echo "양호: 숨겨진 파일 및 디렉터리 없음"
else
  echo "취약: 숨겨진 파일 및 디렉터리 발견"
  echo "$HIDDEN_FILES"
  echo "$HIDDEN_DIRS"
  echo "[조치 방안] 의심스러운 숨겨진 파일 및 디렉터리를 검토 후 삭제하세요."
fi





    echo
    echo
    echo "✅ 파일및디렉토리관리 점검완료!"
    echo
    read -p "🔄 엔터 키를 눌러 계속..."
}

check_service() {



echo
echo
echo " █ U 19 █ Finger 서비스 비활성화"
sleep 1
PROBLEM_FOUND19=1

if [ -f /etc/inetd.conf ]; then
    if grep -qv "^#" /etc/inetd.conf | grep -q "finger"; then
        echo "Finger 서비스가 활성화 되어 있습니다."
        echo "/etc/inetd.conf 파일에서 finger 서비스가 주석 처리되어 있는지 확인하십시오."
        PROBLEM_FOUND19=0
    fi
fi

if [[ "$PROBLEM_FOUND19" -eq 1 ]]; then
    echo "Finger 서비스가 비활성화 되어 있습니다. (양호)"
fi




echo
echo
echo " █ U 20 █ Anonymous FTP 비활성화"
sleep 1
PROBLEM_FOUND20=1

if grep -qE "^ftp:|^anonymous:" /etc/passwd; then
    echo "익명 FTP 접속이 차단되어 있지 않습니다."
    echo "/etc/passwd 파일에서 ftp 또는 anonymous 계정을 삭제하십시오."
    PROBLEM_FOUND20=0
fi

if [[ "$PROBLEM_FOUND20" -eq 1 ]]; then
    echo "익명 FTP 접속이 차단되어 있습니다. (양호)"
fi









echo
echo
echo " █ U 21 █ r 계열 서비스 비활성화"
sleep 1
PROBLEM_FOUND21=1

if ls -alL /etc/xinetd.d/* 2>/dev/null | egrep "rsh|rlogin|rexec" | egrep -v "grep|klogin|kshell|kexec"; then
    echo "r-command 서비스가 활성화 되어 있습니다."
    echo "특별한 용도가 아닌 경우엔 shell(514), login(513), exec(512) 서비스를 중지하십시오."
    PROBLEM_FOUND21=0
fi

if [[ "$PROBLEM_FOUND21" -eq 1 ]]; then
    echo "r-command 서비스가 비활성화 되어 있습니다. (양호)"
fi






echo
echo
echo " █ U 22 █ crond 파일 소유자 및 권한 설정"
sleep 1
PROBLEM_FOUND22=1

CRONTAB_PERM=$(ls -al /usr/bin/crontab | awk '{print $1}')
CRON_FILES="/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d"

if [[ "$CRONTAB_PERM" =~ "rwxrwxrwx" || "$CRONTAB_PERM" =~ "rwxr-xr-x" ]]; then
    echo "Cron 관련 명령어 및 파일의 권한이 적절하지 않습니다."
    echo "crontab 권한 750 이하, cron 관련 파일 소유자 및 권한을 변경하여 주십시오. (소유자 root, 권한 640 이하)"
    PROBLEM_FOUND22=0
fi

for FILE in $CRON_FILES; do
    if [[ -e "$FILE" ]]; then
        FILE_PERM=$(stat -c "%a" "$FILE")
        if [[ "$FILE_PERM" -gt 640 ]]; then
            echo "Cron 관련 명령어 및 파일의 권한이 적절하지 않습니다."
            echo "crontab 권한 750 이하, cron 관련 파일 소유자 및 권한을 변경하여 주십시오. (소유자 root, 권한 640 이하)"
            PROBLEM_FOUND22=0
            break
        fi
    fi
done

if [[ "$PROBLEM_FOUND22" -eq 1 ]]; then
    echo "Cron 관련 명령어 및 파일의 권한이 적절합니다. (양호)"
fi







echo
echo
echo " █ U 23 █ DoS 공격에 취약한 서비스 비활성화"
sleep 1
PROBLEM_FOUND23=1
DOS_SERVICES=("echo" "discard" "daytime" "chargen" "ntp" "dns" "snmp")

for SERVICE in "${DOS_SERVICES[@]}"; do
    if systemctl is-active --quiet "$SERVICE"; then
        echo "DoS 공격에 취약한 서비스들을 중지하거나 활성화 되어 있습니다."
        echo "/etc/xinetd.d/echo, discard, dytime, chargen 파일에서 disable 설정을 yes로 수정하십시오."
        PROBLEM_FOUND23=0
        break
    fi
done

if [[ "$PROBLEM_FOUND23" -eq 1 ]]; then
    echo "DoS 공격에 취약한 서비스들을 중지하거나 비활성화 되어 있습니다. (양호)"
fi







echo
echo
echo " █ U 24 █ NFS 서비스 비활성화"
sleep 1
PROBLEM_FOUND24=1

if ps -ef | egrep "nfs|statd|lockd" | egrep -v "grep" > /dev/null; then
    echo "불필요한 NFS 서비스 관련 데몬이 활성화 되어 있습니다."
    echo "서비스를 제거 한 후, 부팅 시 스크립트 실행 방지를 설정하십시오."
    PROBLEM_FOUND24=0
fi

if [[ "$PROBLEM_FOUND24" -eq 1 ]]; then
    echo "불필요한 NFS 서비스 관련 데몬이 비활성화 되어있습니다. (양호)"
fi







echo
echo
echo " █ U 25 █ NFS 접근 통제"
sleep 1  # 가독성을 위한 대기 시간

# NFS 서비스 상태 확인
nfs_status=$(systemctl is-active nfs-server 2>/dev/null || systemctl is-active nfs-common 2>/dev/null)

echo "NFS 서비스 상태: $nfs_status"

# NFS 서비스가 실행 중이지 않으면 종료
if [[ "$nfs_status" != "active" ]]; then
  echo "NFS 서비스가 실행 중이지 않습니다."
  
fi

# NFS 버전 확인 (rpcinfo를 사용하여 NFS 서비스 버전 확인)
nfs_versions=$(rpcinfo -p | grep -i nfs | awk '{print $3}' | sort -u)

echo "NFS 버전: $nfs_versions"

# NFS 서비스 버전 별로 취약점 확인
nfs_vulnerable=false

for version in $nfs_versions; do
  if [[ "$version" == "2" || "$version" == "3" ]]; then
    echo "NFS v$version 버전은 취약점이 존재하며 평문으로 전송됩니다."
    nfs_vulnerable=true
  fi
done

# NFS v4 상태 확인
nfs_v4_status=$(rpcinfo -p | grep -i "nfs" | grep -w "4")

if [[ -n "$nfs_v4_status" ]]; then
  echo "NFS v4가 활성화되어 있습니다. 보안 강화를 위해 'everyone' 공유를 제한해야 합니다."
  exports_file="/etc/exports"

  # /etc/exports 파일에서 'everyone' 공유 확인
  if grep -q 'everyone' "$exports_file"; then
    echo "주의: 'everyone'으로 설정된 공유가 존재합니다. 공유 권한을 제한하십시오."
    cp "$exports_file" "$exports_file.bak"
    sed -i 's/everyone//g' "$exports_file"
    echo "'everyone' 공유를 제한한 후, /etc/exports를 수정했습니다."
    exportfs -ra
  else
    echo "현재 'everyone' 공유가 설정되어 있지 않습니다."
  fi
else
  echo "NFS v4는 활성화되어 있지 않습니다."
fi







echo
echo
echo " █ U 26 █ automountd 제거"
sleep 1  # 가독성을 위한 대기 시간

# automountd 서비스 상태 확인
automountd_status=$(systemctl is-active automountd 2>/dev/null)

# automountd 서비스가 실행 중인지 확인
if [[ "$automountd_status" == "active" ]]; then
  echo "automountd 서비스가 실행 중입니다."
  echo "경고: 로컬 공격자가 automountd 데몬에 RPC(Remote Procedure Call)를 보낼 수 있는 취약점이 존재합니다."
  echo "해당 서비스는 보안 상 이유로 비활성화해야 합니다."

  # automountd 서비스 중지
  echo "automountd 서비스를 중지합니다..."
  sudo systemctl stop automountd
  echo "automountd 서비스가 중지되었습니다."
else
  echo "automountd 서비스가 실행 중이지 않습니다."
fi

echo "automountd 서비스 점검 완료"







echo
echo
echo " █ U 27 █ 불필요한 RPC 서비스 점검 시작"
sleep 1  # 가독성을 위한 대기 시간


# 점검할 불필요한 RPC 서비스 목록
rpc_services=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")

# 서비스 상태 확인 및 중지
for service in "${rpc_services[@]}"; do
  service_status=$(systemctl is-active "$service" 2>/dev/null)

  if [[ "$service_status" == "active" ]]; then
    echo "$service 서비스가 실행 중입니다."
    echo "경고: $service 서비스는 **불필요한 RPC 서비스**로, 여러 가지 보안 취약점이 존재할 수 있습니다."
    echo "이 서비스들은 버퍼 오버플로우(Buffer Overflow), 서비스 거부(DoS), 원격 실행(Remote Code Execution) 등의 취약
성을 통해"
    echo "비인가자가 root 권한을 획득하거나 시스템을 침해할 위험이 있습니다."
    echo "따라서 보안 상 이유로 해당 서비스를 중지해야 합니다."
    echo "$service 서비스를 중지합니다..."
    sudo systemctl stop "$service"
    echo "$service 서비스가 중지되었습니다."
  else
    echo "$service 서비스는 실행 중이지 않습니다."
  fi
done

echo "불필요한 RPC 서비스 점검 완료"












echo
echo
echo " █ U 28 █ NIS 및 NIS+ 서비스 점검 시작"
sleep 1  # 가독성을 위한 대기 시간

# 점검할 NIS 서비스
nis_services=("ypserv" "ypbind")
# 점검할 NIS+ 서비스
nis_plus_services=("nisplus")

# NIS 서비스 점검 및 비활성화
for service in "${nis_services[@]}"; do
  service_status=$(systemctl is-active "$service" 2>/dev/null)

  if [[ "$service_status" == "active" ]]; then
    echo "$service 서비스가 실행 중입니다."
    echo "경고: $service 서비스는 보안 취약점이 많고, 평문으로 정보를 전송하는 등 위험 요소가 존재합니다."
    echo "NIS 서비스를 사용하지 않는다면 즉시 중지하고 비활성화해야 합니다."
    echo "$service 서비스를 중지합니다..."
    sudo systemctl stop "$service"
    echo "$service 서비스가 중지되었습니다."
  else
    echo "$service 서비스는 실행 중이지 않습니다."
  fi
done
# NIS+ 서비스 점검
for service in "${nis_plus_services[@]}"; do
  service_status=$(systemctl is-active "$service" 2>/dev/null)

  if [[ "$service_status" == "active" ]]; then
    echo "$service 서비스가 실행 중입니다."
    echo "$service 서비스는 NIS의 보안을 강화한 버전입니다. 필요한 경우 활성화해도 좋습니다."
  else
    echo "$service 서비스는 실행 중이지 않습니다."
    echo "$service 서비스가 활성화되지 않았습니다. 만약 보안이 강화된 서비스가 필요하다면 NIS+를 활성화하는 것도 고려할 수 있습니다."
  fi
done

echo "NIS 및 NIS+ 서비스 점검 완료"





echo
echo
echo " █ U 29 █ tftp, talk, ntalk 서비스 비활성화 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간

# 서비스 목록과 서비스 설명
declare -A services
services=(
  ["tftp"]="Trivial File Transfer Protocol (TFTP)는 파일을 전송하는 네트워크 프로토콜로, 보안이 취약하여 악용될 수 있습니다."
  ["talk"]="Talk는 사용자 간 실시간 텍스트 메시지를 주고받는 프로토콜입니다. 보안 취약점이 있어 공격의 대상이 될 수 있습니다."
  ["ntalk"]="ntalk는 Talk 서비스의 확장 버전으로, 같은 이유로 보안에 취약할 수 있습니다."
)

# 서비스 확인 및 종료 함수
check_and_disable_service() {
  service=$1
  description=${services[$service]}

  # 서비스가 실행 중인지 확인
  if systemctl is-active --quiet $service; then
    # 서비스 설명 출력
    echo "$service 서비스는 다음과 같은 취약점을 가질 수 있습니다: $description"
    echo "$service 서비스가 활성화되어 있습니다. 취약점으로 인한 공격을 방지하기 위해 서비스를 종료합니다."

    # 서비스 종료
    sudo systemctl stop $service
    sudo systemctl disable $service
    echo "$service 서비스가 중지되었습니다."
  else
    echo "$service 서비스는 이미 비활성화되어 있습니다."
  fi
}
# 각 서비스에 대해 체크 및 종료 수행
for service in "${!services[@]}"; do
  check_and_disable_service $service
done






echo
echo
echo " █ U 30 █ Sendmail 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간

# Sendmail 버전 점검 및 서비스 점검
check_sendmail_version_and_service() {
  # Sendmail이 설치되어 있는지 확인
  if command -v sendmail &> /dev/null; then
    # Sendmail 버전 확인
    sendmail_version=$(sendmail -d0.1 -bv root 2>&1 | grep 'Version' | awk '{print $2}')

    if [[ -z "$sendmail_version" ]]; then
      echo "Sendmail 버전 확인 실패. 설치된 버전 정보를 가져올 수 없습니다."
      exit 1
    fi

    # 버전이 8.15.2 이하인지 확인
    version_check=$(echo -e "$sendmail_version\n8.15.2" | sort -V | head -n1)

    if [[ "$version_check" == "$sendmail_version" ]]; then
      echo "Sendmail 버전 $sendmail_version은 취약점이 발견된 8.15.2 이하 버전입니다."
      echo "취약점이 발견되었으므로 보안 패치를 설치해야 합니다."
      echo "패치 설치를 위해 http://www.sendmail.org/ 또는 해당 OS 벤더사의 보안 패치를 확인하여 설치하시기 바랍니다."
    else
      echo "Sendmail 버전 $sendmail_version은 안전한 버전입니다."
    fi
 # Sendmail 서비스 실행 여부 확인
    if systemctl is-active --quiet sendmail; then
      echo "Sendmail 서비스가 실행 중입니다. 취약점을 방지하기 위해 해당 서비스를 종료하거나 보안 패치를 적용해야 합니
다."
    else
      echo "Sendmail 서비스는 실행 중이지 않습니다."
    fi
  else
    echo "Sendmail이 설치되지 않았습니다."
  fi
}

# 점검 함수 실행
check_sendmail_version_and_service

echo "Sendmail 점검이 완료되었습니다."






echo
echo
echo " █ U 31 █ Sendmail 서비스 점검 및 릴레이 기능 제한 여부 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간
# Sendmail 서비스 점검 및 릴레이 기능 제한 여부 점검
check_sendmail_relay_restriction() {
  # Sendmail이 설치되어 있는지 확인
  if command -v sendmail &> /dev/null; then
    echo "Sendmail이 설치되어 있습니다."

    # Sendmail 서비스 상태 점검
    if systemctl is-active --quiet sendmail; then
      echo "Sendmail 서비스가 실행 중입니다. 릴레이 기능 제한 여부 점검을 시작합니다."

      # Sendmail 설정 파일 경로
      access_file="/etc/mail/access"

      # 릴레이 제한 설정 점검 (access 파일에 설정된 내용 확인)
      if [ -f "$access_file" ]; then
        # 릴레이 방지를 위한 설정을 찾음
        if grep -q "Connect:ALL REJECT" "$access_file"; then
          echo "Sendmail의 릴레이 기능은 이미 제한되어 있습니다."
        else
          echo "Sendmail의 릴레이 기능이 제한되지 않았습니다."
          echo "릴레이 기능을 방지하려면 '/etc/mail/access' 파일에 다음과 같은 설정을 추가해야 합니다:"
          echo "  Connect:ALL REJECT"
          echo "그리고 다음 명령어로 설정을 적용해야 합니다:"
          echo "  makemap hash /etc/mail/access < /etc/mail/access"
          echo "  systemctl restart sendmail"
        fi
      else
        echo "Sendmail 접근 제어 파일($access_file)이 존재하지 않습니다. /etc/mail 디렉토리의 설정을 점검하세요."
    fi
 else
      echo "Sendmail 서비스가 실행되지 않고 있습니다."
            
  fi
  else
    echo "Sendmail이 설치되지 않았습니다. SMTP 릴레이 점검이 필요하지 않습니다."
  fi
}

# 메인 함수
main() {
  # Sendmail 릴레이 기능 점검
  check_sendmail_relay_restriction
  echo "점검이 완료되었습니다."
}

# 메인 함수 실행
main






echo
echo
echo " █ U 32 █ Sendmail 서비스 점검, q 옵션 제한 여부 점검 및 서비스 중지를 시작합니다"
sleep 1  # 가독성을 위한 대기 시간
# Sendmail 서비스 점검, q 옵션 제한 여부 점검 및 서비스 중지
check_and_configure_sendmail() {
  # Sendmail이 설치되어 있는지 확인
  if command -v sendmail &> /dev/null; then
    echo "Sendmail이 설치되어 있습니다."

    # Sendmail 서비스 상태 점검
    if systemctl is-active --quiet sendmail; then
      echo "Sendmail 서비스가 실행 중입니다. q 옵션 제한 여부 점검을 시작합니다."

      # Sendmail 설정 파일 경로
      sendmail_cf="/etc/mail/sendmail.cf"

      # Sendmail 설정 파일에서 q 옵션과 관련된 설정을 찾음
      if grep -q "O PrivacyOptions=restrictqrun" "$sendmail_cf"; then
        echo "Sendmail에서 'q' 옵션 제한이 설정되어 있습니다."
      else
        echo "Sendmail에서 'q' 옵션 제한이 설정되지 않았습니다."
        echo "'q' 옵션 제한을 설정하려면 '/etc/mail/sendmail.cf' 파일에 다음 라인을 추가해야 합니다:"
        echo "  O PrivacyOptions=restrictqrun"
        echo "그 후 Sendmail을 재시작하여 변경 사항을 적용해야 합니다:"
        echo "  systemctl restart sendmail"
      fi

    else
      echo "Sendmail 서비스가 실행되지 않고 있습니다. 서비스 중지 작업을 수행합니다."
      # 서비스 중지
      systemctl stop sendmail
      echo "Sendmail 서비스가 중지되었습니다."
fi
  else
    echo "Sendmail이 설치되지 않았습니다. 'q' 옵션 점검이 필요하지 않습니다."
  fi
}

# 메인 함수
main() {
  # Sendmail 점검 및 설정
  check_and_configure_sendmail
  echo "점검이 완료되었습니다."
}
# 메인 함수 실행
main





echo
echo
echo " █ U 33 █ BIND 최신버전 사용 유무 및 주기적 보안 패치 여부 점검 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# BIND 설치 여부 확인
if ! command -v named &> /dev/null; then
    echo "⚠️  BIND가 설치되지 않았습니다. 설치 후 다시 실행해 주세요."
    echo "🔹 Ubuntu/Debian: sudo apt install bind9 -y"
    echo "🔹 CentOS/RHEL: sudo yum install bind -y"
    echo "🔹 Alpine Linux: sudo apk add bind"
    echo "🔹 Arch Linux: sudo pacman -S bind"
    echo "=============================================="
    echo "🔴 BIND 최신버전 사용 유무 및 주기적 보안 패치 여부 점검 완료되었습니다."
    echo "=============================================="
    
fi

# 현재 BIND 버전 확인
CURRENT_VERSION=$(named -v | awk '{print $2}')
echo "✅ 현재 BIND 버전: $CURRENT_VERSION"

# 최신 BIND 버전 확인 (ISC 공식 웹사이트 크롤링)
LATEST_VERSION=$(curl -s https://www.isc.org/bind/ | grep -oP 'BIND 9.\d+\.\d+' | head -1 | awk '{print $2}')

if [ -z "$LATEST_VERSION" ]; then
    echo "⚠️  최신 버전 정보를 가져오지 못했습니다. 직접 확인해 주세요: https://www.isc.org/bind/"
    echo "=============================================="
    echo "🔴 BIND 최신버전 사용 유무 및 주기적 보안 패치 여부 점검 완료되었습니다."
    echo "=============================================="
    
fi
echo "🔍 최신 BIND 버전: $LATEST_VERSION"

# 버전 비교
if [ "$CURRENT_VERSION" == "$LATEST_VERSION" ]; then
    echo "✅ 최신 버전을 사용 중입니다!"
else
    echo "⚠️  BIND 업데이트 필요! (현재: $CURRENT_VERSION, 최신: $LATEST_VERSION)"
fi

# 패키지 관리자별 업데이트 확인
echo "🔍 패키지 매니저를 이용한 업데이트 가능 여부 확인 중..."
if command -v apt &> /dev/null; then
    apt update -y > /dev/null 2>&1
    apt list --upgradable 2>/dev/null | grep -q bind && echo "⚠️  BIND 패키지 업데이트 가능!" || echo "✅ 최신 패키지 사용 중!"
elif command -v yum &> /dev/null; then
    yum check-update bind > /dev/null 2>&1 && echo "⚠️  BIND 패키지 업데이트 가능!" || echo "✅ 최신 패키지 사용 중!"
elif command -v dnf &> /dev/null; then
    dnf check-update bind > /dev/null 2>&1 && echo "⚠️  BIND 패키지 업데이트 가능!" || echo "✅ 최신 패키지 사용 중!"
elif command -v zypper &> /dev/null; then
    zypper list-updates | grep -q bind && echo "⚠️  BIND 패키지 업데이트 가능!" || echo "✅ 최신 패키지 사용 중!"
else
    echo "⚠️  지원되지 않는 패키지 관리자입니다. 수동으로 확인해 주세요."
fi

echo "=============================================="
echo "BIND 최신버전 사용 유무 및 주기적 보안 패치 여부 점검 완료되었습니다."
echo "=============================================="




echo
echo
echo " █ U 34 █ Secondary Name Server로만 Zone 정보 전송 제한 점검 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# BIND 설정 파일 경로 (설치된 경로에 맞게 수정)
NAMED_CONF="/etc/named.conf"

# DNS 서비스 상태 점검
echo "[*] DNS(BIND) 서비스 상태 점검 중..."

# BIND가 설치되어 있는지 확인
if systemctl list-units --type=service | grep -q "named.service"; then
    # BIND 서비스가 존재하면, 상태 점검
    if systemctl is-active --quiet named; then
        echo "[+] DNS 서비스가 실행 중입니다."
        
        # Zone Transfer 설정 점검
        echo "[*] Zone Transfer 설정 점검 중..."
        if grep -q "allow-transfer" $NAMED_CONF; then
            echo "[+] Zone Transfer 제한이 설정되어 있습니다."
        else
            echo "[-] Zone Transfer 제한이 설정되지 않았습니다."
            echo "[*] 보안 강화를 위해 Secondary DNS만 허용하도록 설정해야 합니다."
            echo ""
            echo ">>> 수정 방법:"
            echo "1. $NAMED_CONF 파일을 엽니다."
            echo "2. 'options {' 구문 아래에 아래와 같이 추가합니다:"
            echo "    allow-transfer { <허용할 DNS 서버 IP>; };"
            echo "    allow-query { localhost; <허용할 DNS 서버 IP>; };"
            echo "3. 수정 후 파일을 저장하고 닫습니다."
            echo "4. BIND 서비스를 재시작하여 변경 사항을 적용합니다."
            echo "    systemctl restart named"
        fi

        # 서비스 상태 확인
        echo "[*] 적용된 설정 확인:"
        grep "allow-transfer" $NAMED_CONF
        grep "allow-query" $NAMED_CONF

    elif systemctl is-enabled --quiet named; then
        echo "[-] DNS 서비스는 비활성화 상태지만, 설정되어 있습니다."
        echo "[*] DNS 서비스를 중지하고 비활성화하려면 아래 명령어를 사용하세요."
        echo "    systemctl stop named"
        echo "    systemctl disable named"
    else
        echo "[-] DNS 서비스는 실행 중이지 않으며, 설정이 없습니다."
    fi

else
    # BIND가 설치되지 않은 경우
    echo "[-] BIND(DNS) 서비스가 설치되지 않았습니다."
    echo "[*] BIND를 설치하려면 아래 명령어를 사용하세요:"
    echo "    sudo dnf install bind"
    echo "[*] 설치 후 서비스를 시작하고 설정을 진행해주세요."
fi

echo "[+] 점검 완료! 필요한 설정 변경을 수동으로 하시길 바랍니다."











echo
echo
echo " █ U 35 █ 디렉터리 검색 기능의 활성화 여부 점검 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# Apache 설정 파일 경로
HTTPD_CONF="/etc/httpd/conf/httpd.conf"  # CentOS/RHEL 기반
# HTTPD_CONF="/etc/apache2/apache2.conf"  # Ubuntu/Debian 기반, 주석 처리된 부분은 필요에 따라 사용

# httpd.conf 파일이 존재하는지 확인
if [ ! -f "$HTTPD_CONF" ]; then
    echo "⚠️  Apache 설정 파일이 존재하지 않습니다. 경로를 확인하십시오: $HTTPD_CONF"
    echo "=============================================="
    echo "🔴 디렉터리 검색 기능의 활성화 여부 점검 완료되었습니다."
    echo "=============================================="
   
fi

# 디렉터리 검색 기능 점검: 'Indexes' 옵션이 있는지 확인
echo "🔍 Apache 설정 파일에서 디렉터리 검색 기능(Indexes) 점검 중..."
INDEXES_FOUND=$(grep -i "Options.*Indexes" $HTTPD_CONF)

if [ -z "$INDEXES_FOUND" ]; then
    echo "✅ 디렉터리 검색 기능(Indexes)은 활성화되지 않았습니다."
else
    echo "⚠️ 디렉터리 검색 기능(Indexes)이 활성화되어 있습니다."
    echo "   활성화된 설정: $INDEXES_FOUND"
    echo "🔧 해결 방법: 디렉터리 검색 기능을 비활성화하려면, 'Options' 지시자에서 'Indexes' 옵션을 제거해야 합니다."
fi

# 해결 방법 안내
echo "🔧 조치 방법: httpd.conf 파일에서 모든 'Options' 지시자에서 'Indexes' 옵션을 제거하십시오."
echo "  예시: "
echo "  Options -Indexes"

echo "=============================================="
echo "✅ 디렉터리 검색 기능의 활성화 여부 점검 완료되었습니다."
echo "=============================================="






echo
echo
echo " █ U 36 █ Apache 데몬이 root 권한으로 구동되는지 여부 점검 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# Apache 데몬 프로세스 확인
APACHE_PID=$(ps aux | grep '[a]pache2\|[h]ttpd' | awk '{print $1}')

if [ -z "$APACHE_PID" ]; then
    echo "⚠️ Apache 데몬이 실행 중이 아닙니다."
    echo "=============================================="
    echo "🔴 Apache 데몬 root 권한 구동 여부 점검 완료되었습니다."
    echo "=============================================="
   
fi

# Apache 데몬이 root 권한으로 실행 중인지 확인
if [ "$APACHE_PID" == "root" ]; then
    echo "⚠️ Apache 데몬이 root 권한으로 구동 중입니다."
    echo "   현재 실행 중인 사용자: root"
    echo "🔧 해결 방법: Apache 데몬을 root 권한이 아닌 별도 계정으로 구동해야 합니다."
else
    echo "✅ Apache 데몬은 root 권한이 아닌 사용자로 구동 중입니다."
    echo "   현재 실행 중인 사용자: $APACHE_PID"
fi

# 해결 방법 안내
echo "🔧 조치 방법: Apache 데몬을 별도의 비루트 사용자 계정으로 구동하기 위해서는 httpd.conf 파일에서 User와 Group을 설정해야 합니다."
echo "  예시: "
echo "  User apache"
echo "  Group apache"

echo "=============================================="
echo "✅ Apache 데몬이 root 권한으로 구동되는지 여부 점검 완료되었습니다."
echo "=============================================="





echo
echo
echo " █ U 37 █ 상위 경로로 이동이 가능한지 여부 점검 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# Apache 설정 파일 경로
HTTPD_CONF="/etc/httpd/conf/httpd.conf"  # 로키 리눅스의 기본 Apache 설정 파일 경로

# httpd.conf 파일이 존재하는지 확인
if [ ! -f "$HTTPD_CONF" ]; then
    echo "⚠️ Apache 설정 파일이 존재하지 않습니다. 경로를 확인하십시오: $HTTPD_CONF"
    echo "=============================================="
    echo "🔴 상위 경로로 이동이 가능한지 여부 점검 완료되었습니다."
    echo "=============================================="
   
fi

# ".." 사용하여 상위 경로로 이동 가능 여부 점검
echo "🔍 '..'를 사용하여 상위 경로로 이동이 가능한지 점검 중..."
cd /var/www/html || { echo "⚠️ 디렉토리 이동 실패"; exit 1; }

# 파일 시스템 권한 점검
echo "🔧 상위 경로로 이동이 허용되었는지 점검 중..."
if [ -w ".." ]; then
    echo "⚠️ '..'를 사용하여 상위 디렉토리로 이동이 가능합니다."
else
    echo "✅ '..'를 사용하여 상위 디렉토리로 이동이 제한되었습니다."
fi

# 사용자 인증을 설정할 디렉토리 점검
echo "🔧 httpd.conf 파일에서 AllowOverride 설정 점검 중..."
ALLOW_OVERRIDE=$(grep -i "AllowOverride" $HTTPD_CONF)

if [[ "$ALLOW_OVERRIDE" == *"None"* ]]; then
    echo "⚠️ AllowOverride가 'None'으로 설정되어 있어 .htaccess 파일이 작동하지 않습니다."
    echo "🔧 해결 방법: AllowOverride 지시자를 'AuthConfig' 또는 'All'로 변경해야 합니다."
else
    echo "✅ AllowOverride 지시자가 적절히 설정되어 있습니다."
fi

# 해결 방법 안내
echo "🔧 조치 방법:"
echo "1. 사용자 인증을 하기 위해 각 디렉터리 별로 httpd.conf 파일 내 AllowOverride 지시자의 옵션을 'None'에서 'AuthConfig' 또는 'All'로 변경합니다."
echo "   예시:"
echo "   AllowOverride AuthConfig"
echo "2. 사용자 인증을 설정할 디렉터리에 .htaccess 파일을 생성합니다."
echo "3. 사용자 인증 계정을 생성하려면 아래 명령어를 사용하십시오:"
echo "   htpasswd -c <인증 파일> <사용자 계정>"

echo "=============================================="
echo "✅ 상위 경로로 이동이 가능한지 여부 점검 완료되었습니다."
echo "=============================================="







echo
echo
echo " █ U 38 █ Apache 설치 시 기본으로 생성되는 불필요한 파일의 삭제 여부 점검 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# Apache 설치 경로 (일반적으로 /var/www/html, 또는 /usr/local/apache2)
APACHE_HOME="/var/www/html"  # 기본 경로로 설정되어 있음. 필요시 변경.
MANUAL_DIR="$APACHE_HOME/manual"
HDOCTS_MANUAL_DIR="$APACHE_HOME/htdocs/manual"

# 불필요한 파일/디렉터리 점검
echo "🔍 불필요한 파일 및 디렉터리 점검 중..."

# /[Apache_home]/htdocs/manual 디렉터리 존재 여부 점검
if [ -d "$HDOCTS_MANUAL_DIR" ]; then
    echo "⚠️ $HDOCTS_MANUAL_DIR 디렉터리가 존재합니다."
else
    echo "✅ $HDOCTS_MANUAL_DIR 디렉터리는 존재하지 않습니다."
fi

# /[Apache_home]/manual 디렉터리 존재 여부 점검
if [ -d "$MANUAL_DIR" ]; then
    echo "⚠️ $MANUAL_DIR 디렉터리가 존재합니다."
else
    echo "✅ $MANUAL_DIR 디렉터리는 존재하지 않습니다."
fi

# 삭제 방법 안내
echo "🔧 불필요한 파일 및 디렉터리를 제거하려면 아래 명령어를 사용하십시오:"
echo "   rm -rf $HDOCTS_MANUAL_DIR"
echo "   rm -rf $MANUAL_DIR"

echo "=============================================="
echo "✅ Apache 설치 시 기본으로 생성되는 불필요한 파일의 삭제 여부 점검 완료되었습니다."
echo "=============================================="






echo
echo
echo " █ U 39 █ 심볼릭 링크, aliases 사용 제한 여부 점검 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# Apache 설정 파일 경로 (일반적으로 /etc/httpd/conf/httpd.conf)
HTTPD_CONF="/etc/httpd/conf/httpd.conf"  # 로키 리눅스의 기본 Apache 설정 파일 경로

# httpd.conf 파일이 존재하는지 확인
if [ ! -f "$HTTPD_CONF" ]; then
    echo "⚠️ Apache 설정 파일이 존재하지 않습니다. 경로를 확인하십시오: $HTTPD_CONF"
    echo "=============================================="
    echo "🔴 심볼릭 링크, aliases 사용 제한 여부 점검 완료되었습니다."
    echo "=============================================="
   
fi

# "FollowSymLinks" 옵션 점검
echo "🔍 심볼릭 링크(FollowSymLinks) 사용 여부 점검 중..."

# httpd.conf 파일에서 FollowSymLinks 옵션이 포함된 라인 찾기
SYMLINK_OPTION=$(grep -i "FollowSymLinks" "$HTTPD_CONF")

if [ -n "$SYMLINK_OPTION" ]; then
    echo "⚠️ httpd.conf 파일에서 FollowSymLinks 옵션이 설정되어 있습니다."
else
    echo "✅ httpd.conf 파일에서 FollowSymLinks 옵션이 설정되지 않았습니다."
fi

# aliases 사용 제한 여부 점검
echo "🔍 aliases 사용 여부 점검 중..."
ALIAS_OPTION=$(grep -i "Alias" "$HTTPD_CONF")

if [ -n "$ALIAS_OPTION" ]; then
    echo "⚠️ httpd.conf 파일에서 Alias 옵션이 설정되어 있습니다."
else
    echo "✅ httpd.conf 파일에서 Alias 옵션이 설정되지 않았습니다."
fi

# 해결 방법 안내
echo "🔧 해결 방법:"
echo "1. 심볼릭 링크를 사용하지 않도록 설정하려면 httpd.conf 파일에서 모든 디렉터리의 Options 지시자에서 FollowSymLinks 옵션을 제거합니다."
echo "   예시: "
echo "   <Directory /var/www/html>"
echo "       Options -FollowSymLinks"
echo "   </Directory>"

echo "2. Alias 사용을 제한하려면 Alias 관련 설정을 주석 처리하거나 삭제합니다."
echo "   예시: "
echo "   # Alias /manual /usr/share/httpd/manual"

echo "=============================================="
echo "✅ 심볼릭 링크, aliases 사용 제한 여부 점검 완료되었습니다."
echo "=============================================="







echo
echo
echo " █ U 40 █ 파일 업로드 및 다운로드 사이즈 제한 여부 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# 파일 업로드 및 다운로드 사이즈 제한 여부 점검
check_upload_download_limit() {
    echo "🔍 파일 업로드 및 다운로드 사이즈 제한 여부 점검 중..."

    HTTPD_CONF="/etc/httpd/conf/httpd.conf"  # Apache 설정 파일 경로

    if [ ! -f "$HTTPD_CONF" ]; then
        echo "⚠️ Apache 설정 파일이 존재하지 않습니다. 경로를 확인하십시오: $HTTPD_CONF"
        return
    fi

    # LimitRequestBody 지시자가 설정되어 있는지 점검
    LIMIT_REQUEST_BODY=$(grep -i "LimitRequestBody" "$HTTPD_CONF")

    if [ -n "$LIMIT_REQUEST_BODY" ]; then
        echo "✅ LimitRequestBody 지시자가 설정되어 있습니다."
    else
        echo "⚠️ LimitRequestBody 지시자가 설정되지 않았습니다. 파일 업로드 및 다운로드 사이즈 제한이 설정되지 않았습니다."
    fi

    # 조치 방법 안내
    echo "🔧 해결 방법:"
    echo "1. 파일 사이즈 제한을 설정하려면 httpd.conf 파일에서 적절한 디렉터리에 LimitRequestBody 지시자를 추가하십시오."
    echo "   예: LimitRequestBody 10485760  # 10MB로 제한"
    echo "=============================================="
}

# 점검 함수 실행
check_upload_download_limit

# 점검 완료 메시지
echo "=============================================="
echo "✅ 파일 업로드 및 다운로드 사이즈 제한 여부 점검이 완료되었습니다."
echo "=============================================="




echo
echo
echo " █ U 41 █ 웹 서버의 루트 디렉터리와 OS의 루트 디렉터리 다르게 지정되었는지 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간

# 웹 서버 루트 디렉터리 점검 함수
check_document_root() {
    echo "🔍 웹 서버의 루트 디렉터리 점검 중..."

    HTTPD_CONF="/etc/httpd/conf/httpd.conf"  # Apache 설정 파일 경로

    if [ ! -f "$HTTPD_CONF" ]; then
        echo "⚠️ Apache 설정 파일이 존재하지 않습니다. 경로를 확인하십시오: $HTTPD_CONF"
        return
    fi

    # DocumentRoot 설정을 확인
    DOCUMENT_ROOT=$(grep -i "DocumentRoot" "$HTTPD_CONF" | awk '{print $2}')

    if [ -z "$DOCUMENT_ROOT" ]; then
        echo "⚠️ DocumentRoot 설정이 없습니다. 설정을 확인하십시오."
        return
    fi

    echo "✅ 설정된 DocumentRoot: $DOCUMENT_ROOT"

    # DocumentRoot가 OS의 루트 디렉터리 내에 있는지 확인
    if [[ "$DOCUMENT_ROOT" =~ ^/(etc|bin|sbin|usr) ]]; then
        echo "⚠️ DocumentRoot가 시스템 중요 디렉터리 내부에 설정되어 있습니다."
        echo "   (예: /etc, /bin, /usr)"
    else
        echo "✅ DocumentRoot는 시스템 중요 디렉터리 외부에 설정되어 있습니다."
    fi

    # 조치 방법 안내
    echo "🔧 해결 방법:"
    echo "1. DocumentRoot가 시스템 디렉터리(예: /etc, /bin, /sbin, /usr 등) 내에 설정되어 있다면 /www와 같이 별도의 디렉터리를 생성하여 웹 서버의 루트 디렉터리를 설정해야 합니다."
    echo "   예: DocumentRoot \"/www/htdocs\""
    echo "=============================================="
}

# 점검 함수 실행
check_document_root

# 점검 완료 메시지
echo "=============================================="
echo "✅ 웹 서버의 루트 디렉터리 점검이 완료되었습니다."
echo "=============================================="



echo
echo
echo " █ U 60 █ SSH 원격 접속 허용 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

SSH_STATUS=$(ss -tuln | grep ':22')
if [ -n "$SSH_STATUS" ]; then
  echo "양호: SSH 서비스가 활성화되어 있음"
else
  echo "취약: SSH 서비스가 비활성화 되어 있음"
  echo "[조치 방안] SSH 서비스 활성화: systemctl start sshd"
fi





echo
echo
echo " █ U 61 █ FTP 서비스 확인 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

FTP_STATUS=$(ps -ef | grep -E "vsftpd|proftpd" | grep -v grep)
if [ -z "$FTP_STATUS" ]; then
  echo "양호: FTP 서비스가 비활성화 되어 있음"
else
  echo "취약: FTP 서비스가 활성화되어 있음"
  echo "$FTP_STATUS"
  echo "[조치 방안] FTP 서비스 비활성화: systemctl stop vsftpd"
fi





echo
echo
echo " █ U 62 █ FTP 계정 shell 제한 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

FTP_SHELL=$(cat /etc/passwd | grep ^ftp: | awk -F: '{print $7}')
if [ "$FTP_SHELL" == "/bin/false" ] || [ "$FTP_SHELL" == "/sbin/nologin" ]; then
  echo "양호: FTP 계정이 shell 접근 제한됨"
else
  echo "취약: FTP 계정이 shell 접근 가능"
  echo "[조치 방안] FTP 계정의 shell 제한: usermod -s /bin/false ftp"
fi





echo
echo
echo " █ U 63 █ ftpusers 파일 소유자 및 권한 설정 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

FTPUSERS_FILE="/etc/ftpusers"
if [ -f "$FTPUSERS_FILE" ]; then
  PERM=$(stat -c "%a" $FTPUSERS_FILE)
  OWNER=$(stat -c "%U" $FTPUSERS_FILE)
  if [ "$OWNER" == "root" ] && [ $PERM -le 640 ]; then
    echo "양호: ftpusers 파일의 소유자가 root이고 권한이 640 이하임"
  else
    echo "취약: ftpusers 파일 소유자 또는 권한 설정 불충분"
    echo "[조치 방안] ftpusers 파일의 소유자를 root로 변경하고 권한을 640 이하로 설정: chown root $FTPUSERS_FILE; chmod 640 $FTPUSERS_FILE"
  fi
else
  echo "양호: ftpusers 파일이 존재하지 않음"
fi





echo
echo
echo " █ U 64 █ FTP root 계정 접근 제한 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

if grep -q "^root" $FTPUSERS_FILE 2>/dev/null; then
  echo "양호: ftpusers 파일에 root 계정이 등록됨"
else
  echo "취약: ftpusers 파일에 root 계정이 등록되지 않음"
  echo "[조치 방안] ftpusers 파일에 root 계정 추가: echo 'root' >> $FTPUSERS_FILE"
fi









echo
echo
echo " █ U 65 █ at 서비스 권한 설정 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

AT_ALLOW="/etc/at.allow"
AT_DENY="/etc/at.deny"
if [ -f "$AT_ALLOW" ] && [ ! -f "$AT_DENY" ]; then
  echo "양호: at.allow 파일만 존재함"
else
  echo "취약: at 서비스가 허술하게 설정됨"
  echo "[조치 방안] at.allow 파일 생성 후 root 외 사용자 제거: echo root > $AT_ALLOW; rm -f $AT_DENY"
fi







echo
echo
echo " █ U 66 █ SNMP 서비스 구동 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

SNMP_STATUS=$(ps -ef | grep snmp | grep -v grep)
if [ -z "$SNMP_STATUS" ]; then
  echo "양호: SNMP 서비스가 비활성화 됨"
else
  echo "취약: SNMP 서비스가 활성화됨"
  echo "$SNMP_STATUS"
  echo "[조치 방안] SNMP 서비스 중지: systemctl stop snmpd"
fi






echo
echo
echo " █ U 67 █ SNMP Community String 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

if grep -E "public|private" /etc/snmp/snmpd.conf 2>/dev/null; then
  echo "취약: SNMP Community String이 기본 값 사용(public/private)"
  echo "[조치 방안] snmpd.conf 파일 수정: vi /etc/snmp/snmpd.conf -> public/private 값을 변경"
else
  echo "양호: SNMP Community String이 보안 설정됨"
fi






echo
echo
echo " █ U 68 █ 로그온 경고 메시지 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

motd_content=$(cat /etc/motd 2>/dev/null)
if [ -n "$motd_content" ]; then
    echo "양호: 경고 메시지 설정 완료"
else
    echo "취약: 경고 메시지가 설정되지 않음!"
    echo "🛠️  해결 방안: /etc/motd 파일에 경고 메시지 추가"
fi





echo
echo
echo " █ U 69 █ NFS 접근 제어 설정 파일 권한 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

file="/etc/exports"

if [ -f "$file" ]; then
  owner=$(stat -c %U $file)
  perm=$(stat -c %a $file)

  echo "NFS 접근 제어 설정 파일 소유자: $owner"
  echo "NFS 접근 제어 설정 파일 권한: $perm"

  if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
    echo "양호: NFS 접근 제어 설정 파일 소유자가 root이며 권한이 644 이하입니다."
  else
    echo "취약: NFS 접근 제어 설정 파일 소유자나 권한이 적절하지 않습니다."
    echo "---조치 방법---"
    echo "/etc/exports 파일의 소유자 및 권한 변경 (소유자root, 권한 644)"
    echo "chown root /etc/exports  //소유자를 root로 변환"
    echo "chmod 644 /etc/exports   // 권한을 644로 변환"
  fi
else
  echo "NFS 접근 제어 설정 파일이 존재하지 않습니다."
fi






echo
echo
echo " █ U 70 █ expn, vrfy 명령어 제한 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

file="/etc/mail/sendmail.cf"

if [ -f "$file" ]; then
  result=$(grep -E "O PrivacyOptions=.*noexpn.*novrfy" $file)

  if [ -n "$result" ]; then
    echo "양호: expn, vrfy 명령어가 제한되어 있습니다."
  else
    echo "취약: expn, vrfy 명령어가 제한되지 않았습니다."
    echo "---서비스 필요 시 조치 방법---"
    echo "SMTP 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가"
    echo "vi편집기를 이용하여 /etc/mail/sendmail.cf 파일을 연 후 noexpn, novrfy 옵션 추가하기."
    echo "vi /etc/mail/sendmail.cf"
    echo "---서비스 불필요 시 조치 방법---"
    echo "step 1) 실행 중인 서비스 중지
    echo "ps -ef | grep sendmail
    echo "root 441 1 0 Sep19 ? 00:00:00 sendmail: accepting connections"
    echo "step 2) 시스템 재시작 시 SMTP 서버가 시작되지 않도록 OS별로 아래와 같이 설정함"
    echo "1. 위치 확인  // ls -al /etc/rc*.d/* | grep sendmail"
    echo "2. 이름 변경  // mv /etc/rc2.d/S88sendmail /etc/rc2.d/_S88sendmail"
  fi
else
  echo "Sendmail 설정 파일이 존재하지 않습니다."
fi






echo
echo
echo " █ U 71 █ Apache 웹 서비스 정보 숨김 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

httpd_conf="/etc/httpd/conf/httpd.conf"

if [ -f "$httpd_conf" ]; then
  tokens=$(grep -i "ServerTokens" $httpd_conf)
  signature=$(grep -i "ServerSignature" $httpd_conf)
 if [[ "$tokens" == *"Prod"* ]] && [[ "$signature" == *"Off"* ]]; then
    echo "양호: Apache 웹 서비스 정보가 숨겨져 있습니다."
  else
    echo "취약: Apache 웹 서비스 정보가 노출될 수 있습니다."
    echo "---조치 방법---"
    echo "헤더에 최소한의 정보를 제한 후 전송(ServerTokens 지시자에 prod 옵션, ServerSignature 지시자에 Off 옵션 설정)"
    echo "Step 1) vi편집기를 이용하여 /[Apache_home]/conf/httpd.conf 파일 열기"
    echo "vi /[Apache_home]/conf/httpd.conf"
    echo "Step 2) 설정된 모든 디렉터리의 ServerTokens 지시자에>서 Prod 옵션 설정 및 ServerSignature Off 지시자에 Off 옵션 설정(없으면 신규 삽입)"
  fi
else
  echo "Apache 설정 파일이 존재하지 않습니다."
fi





    echo
    echo
    echo "✅ 서비스관리 점검완료!"
    echo
    read -p "🔄 엔터 키를 눌러 계속..."
}

check_patch() {



echo
echo
echo " █ U 42 █ 시스템에서 최신 패치가 적용되어 있는지 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# 최신 패치 적용 여부 점검 함수
check_system_patch() {
    echo "🔍 시스템에서 최신 패치가 적용되어 있는지 점검 중..."

    # OS에 따라 패치 확인 방법이 달라짐 (예: CentOS, Ubuntu, Debian 등)
    if [ -f /etc/redhat-release ]; then
        # Red Hat 계열 (CentOS, RHEL)
        PACKAGE_MANAGER="yum"
        if command -v "$PACKAGE_MANAGER" >/dev/null 2>&1; then
            echo "✅ 패키지 관리자: $PACKAGE_MANAGER"
            # 시스템 패치 여부 점검 (업데이트된 패키지가 있는지 확인)
            UPDATES=$(yum check-update | wc -l)
            if [ "$UPDATES" -gt 0 ]; then
                echo "⚠️ 최신 패치가 적용되지 않았습니다. 시스템에 $UPDATES 개의 업데이트가 필요합니다."
            else
                echo "✅ 시스템에 최신 패치가 모두 적용되어 있습니다."
            fi
        else
            echo "⚠️ 패키지 관리자 ($PACKAGE_MANAGER)가 설치되지 않았습니다. 시스템 관리자에게 문의하십시오."
        fi
    elif [ -f /etc/lsb-release ] || [ -f /etc/debian_version ]; then
        # Debian 계열 (Ubuntu, Debian)
        PACKAGE_MANAGER="apt"
        if command -v "$PACKAGE_MANAGER" >/dev/null 2>&1; then
            echo "✅ 패키지 관리자: $PACKAGE_MANAGER"
            # 시스템 패치 여부 점검 (업데이트된 패키지가 있는지 확인)
            UPDATES=$(apt list --upgradable 2>/dev/null | wc -l)
            if [ "$UPDATES" -gt 0 ]; then
                echo "⚠️ 최신 패치가 적용되지 않았습니다. 시스템에 $UPDATES 개의 업데이트가 필요합니다."
            else
                echo "✅ 시스템에 최신 패치가 모두 적용되어 있습니다."
            fi
        else
            echo "⚠️ 패키지 관리자 ($PACKAGE_MANAGER)가 설치되지 않았습니다. 시스템 관리자에게 문의하십시오."
        fi
    else
        echo "⚠️ 지원되지 않는 시스템입니다. (Red Hat 계열 또는 Debian 계열)"
    fi

    # 조치 방법 안내
    echo "🔧 해결 방법:"
    echo "1. O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 패치를 적용합니다."
    echo "2. OS 패치의 경우 지속적으로 취약점이 발표되고 있기 때문에 주기적인 패치 적용 정책을 수립하여야 합니다."
    echo "   패치 적용 후 서비스에 미치는 영향을 충분히 고려하십시오."
    echo "=============================================="
}

# 점검 함수 실행
check_system_patch


    echo
    echo
    echo "✅ 패치관리 점검완료!"
    echo
    read -p "🔄 엔터 키를 눌러 계속..."
}

check_log() {

echo
echo
echo " █ U 43 █ 로그의 정기적 검토 및 보고 여부 점검을 시작합니다"
sleep 1  # 가독성을 위한 대기 시간


# 로그 검토 여부 점검 함수
check_log_review() {
    echo "🔍 로그의 정기적 검토 및 보고 여부 점검 중..."

    # 시스템의 주요 로그 파일 목록
    LOG_FILES=(
        "/var/log/syslog"
        "/var/log/messages"
        "/var/log/auth.log"
        "/var/log/apache2/access.log"
        "/var/log/apache2/error.log"
        "/var/log/cron"
    )

    # 로그 파일들의 존재 여부를 점검
    for LOG_FILE in "${LOG_FILES[@]}"; do
        if [ -f "$LOG_FILE" ]; then
            echo "✅ 로그 파일: $LOG_FILE 존재"
        else
            echo "⚠️ 로그 파일: $LOG_FILE이 존재하지 않거나 접근할 수 없습니다."
        fi
    done

    # 정기적인 로그 검토 및 보고 여부 점검 (예: 최근 30일 이내의 로그 파일 검토 여부)
    echo "🔍 최근 30일 이내의 로그 파일을 검토했는지 확인 중..."
    LOG_REVIEWED=0
    for LOG_FILE in "${LOG_FILES[@]}"; do
        if [ -f "$LOG_FILE" ]; then
            # 마지막 수정 시간을 확인 (30일 이상 되지 않았으면 검토 필요)
            LAST_MODIFIED=$(stat --format="%Y" "$LOG_FILE")
            CURRENT_TIME=$(date +%s)
            DIFF_TIME=$((CURRENT_TIME - LAST_MODIFIED))
            DIFF_DAYS=$((DIFF_TIME / 86400))

            if [ "$DIFF_DAYS" -le 30 ]; then
                LOG_REVIEWED=1
            fi
        fi
    done

    if [ "$LOG_REVIEWED" -eq 1 ]; then
        echo "✅ 최근 30일 이내의 로그 파일 검토가 이루어졌습니다."
    else
        echo "⚠️ 최근 30일 이내에 로그 파일 검토가 이루어지지 않았습니다."
    fi

    # 조치 방법 안내
    echo "🔧 해결 방법:"
    echo "1. 시스템의 주요 로그 파일을 정기적으로 검토하고 분석하여 리포트를 작성합니다."
    echo "2. 정기적인 로그 검토 및 보고를 수행하여 시스템의 보안과 운영 상태를 모니터링합니다."
    echo "3. 로그 파일은 주기적으로 분석하고, 문제가 발생하면 즉시 보고할 수 있도록 해야 합니다."
    echo "=============================================="
}

# 점검 함수 실행
check_log_review






echo
echo
echo " █ U 72 █ 시스템 로깅 설정 점검을 시작합니다."

sleep 1  # 가독성을 위한 대기 시간

syslog_conf="/etc/rsyslog.conf"

if [ -f "$syslog_conf" ]; then
  grep -E "auth|authpriv|cron|daemon|kern|lpr|mail|news|syslog|user|uucp|local" $syslog_conf
  echo "로깅 설정이 위와 같이 구성되어 있는지 확인하세요."
else
  echo "[취약] syslog 설정 파일이 존재하지 않습니다."
  echo "---조치 방법---"
  echo "로그 기록 정책을 수립하고, 정책에 따라 syslog.conf 파일을 설정"
  echo "Step 1) vi 편집기를 이용하여 "/etc/syslog.conf" 파일 열기"
  echo "vi /etc/syslog.conf"
  echo "Step 2) 수정 또는, 신규 삽입"
  echo "ex) mail.* -> /var/log/maillog"
  echo "ex2) cron.* -> /var/log/cron"
  echo "Step 3) 위와 같이 설정 후 SYSLOG 데몬 재시작"
  echo "ps -ef |grep syslogd"
  echo "root 7524 6970 0 Apr 23 - 0:02 /usr/sbin/syslogd"
  echo "kill -HUP [PID]"
fi




    echo
    echo
    echo "✅ 로그관리 점검완료"
    echo
    read -p "🔄 엔터 키를 눌러 계속..."
}

# 점검 메뉴 (반복 실행)
while true; do
    clear  # 화면 정리 후 메뉴 출력
	DATE=$(date "+%Y-%m-%d %H:%M:%S")
	echo "*************************************************************"
	echo "* ███████╗███╗   ██╗  ╔═══════════════════════════════════╗ *"
	echo "* ██╔════╝████╗  ██║  ║  EN Team Project Security Script  ║ *"
	echo "* █████╗  ██╔██╗ ██║  ║                                   ║ *"
	echo "* ██╔══╝  ██║╚██╗██║  ║  Vulnerability Scanning DATE :    ║ *"
	echo "* ███████╗██║ ╚████║  ║  ${DATE}              ║ *"
	echo "* ╚══════╝╚═╝  ╚═══╝  ╚═══════════════════════════════════╝ *"
	echo "*************************************************************"
	echo
    echo "=============================================="
    echo "📌 실행할 점검 항목을 선택하세요:"
    echo "1) 계정관리 점검"
    echo "2) 파일및디렉토리관리 점검"
    echo "3) 서비스관리 점검"
    echo "4) 패치관리 점검"
    echo "5) 로그관리 점검"
    echo "0) 종료"
    echo "=============================================="
    
    read -p "▶ 번호를 입력하세요: " choice
    
    case "$choice" in
        1) check_account ;;
        2) check_file_dir ;;
        3) check_service ;;
        4) check_patch ;;
        5) check_log ;;
        0) 
            echo "🛑 점검 스크립트를 종료합니다."
            exit 0
            ;;
        *) 
            echo "⚠️  올바른 번호를 입력하세요!"
            read -p "🔄 엔터 키를 눌러 계속..."
            ;;
    esac
done


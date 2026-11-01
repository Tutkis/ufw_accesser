#!/bin/bash

# Проверяем, что скрипт запущен от имени root
if [ "$EUID" -ne 0 ]; then
  echo "Пожалуйста, запустите скрипт от имени root (sudo)."
  exit 1
fi

DIR="/opt/accesser"
RULES_FILE="$DIR/rules"
SCRIPT_FILE="$DIR/update.sh"

echo "=== 1. Проверка и установка системных зависимостей (UFW, SSH, DNS) ==="

# Обновляем кэш пакетов
apt update -y

# Проверка и установка OpenSSH Server
if ! command -v sshd &> /dev/null && ! dpkg -s openssh-server &> /dev/null; then
    echo "SSH-сервер не найден. Устанавливаем openssh-server..."
    apt install openssh-server -y
    systemctl enable --now ssh
else
    echo "[ОК] OpenSSH Server уже установлен."
fi

# Определяем актуальный порт SSH из конфига (поддерживает кастомные порты)
SSH_PORT=$(grep -E "^Port [0-9]+" /etc/ssh/sshd_config | awk '{print $2}')
: ${SSH_PORT:=22} # Если порт не найден в явном виде, используем дефолтный 22
echo "Определен текущий порт SSH на сервере: $SSH_PORT"

# Проверка и установка UFW
if ! command -v ufw &> /dev/null; then
    echo "Брандмауэр UFW не найден. Устанавливаем..."
    apt install ufw -y
else
    echo "[ОК] UFW уже установлен."
fi

# Проверка утилиты host (dnsutils) для работы с доменами
if ! command -v host &> /dev/null; then
    echo "Утилита 'host' не найдена. Устанавливаем dnsutils..."
    apt install dnsutils -y
fi

echo "=== 2. Подготовка папок ==="
mkdir -p "$DIR"

echo "=== 3. Создание файла правил (rules) с псевдонимами ==="
# Если файл правил еще не существует, создаем шаблон
if [ ! -f "$RULES_FILE" ]; then
    cat << EOF > "$RULES_FILE"
# ====================================================================
# БЛОК ПСЕВДОНИМОВ (АЛИАСОВ)
# Формат: alias | имя_псевдонима | порт/протокол
# ====================================================================
alias | ssh       | ${SSH_PORT}/tcp
alias | http      | 80/tcp
alias | https     | 443/tcp
alias | proxy     | 8080/tcp
alias | wireguard | 51820/udp

# ====================================================================
# БЛОК ПРАВИЛ ДОСТУПА
# Формат: ТИП | ИСТОЧНИК (домен/IP/any) | НАЗНАЧЕНИЕ (псевдоним или порт/протокол)
# Допустимые ТИПы: allow, deny, icmp
# ====================================================================
allow | dom1.sluzhebny.tutkis.ru | ssh
allow | dom2.sluzhebny.tutkis.ru | ssh
allow | office.tutkis.ru        | proxy
allow | any                     | http
allow | any                     | https
icmp  | pinger.tutkis.ru        | any
EOF
    echo "Создан дефолтный файл правил: $RULES_FILE"
else
    echo "Файл правил $RULES_FILE уже существует, пропускаем."
fi

echo "=== 4. Создание исполнительного скрипта обновления ==="
cat << 'EOF' > "$SCRIPT_FILE"
#!/bin/bash
# Скрипт автоматического обновления правил UFW на основе DNS-имен и алиасов
#
# Улучшения:
#   * flock — защита от одновременного запуска (например, при сбое cron)
#   * Поддержка IPv6 (AAAA-записи) наряду с IPv4 (A)
#
RULES_FILE="/opt/accesser/rules"
LOCK_FILE="/opt/accesser/update.lock"

if [ ! -f "$RULES_FILE" ]; then
    echo "Файл правил не найден!"
    exit 1
fi

exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "Другой экземпляр скрипта уже запущен — выхожу."
    exit 1
fi

# Сначала парсим все алиасы из файла правил во внутренний ассоциативный массив bash
declare -A ALIASES
while IFS='|' read -r type name val || [ -n "$type" ]; do
    type=$(echo "$type" | xargs)
    name=$(echo "$name" | xargs)
    val=$(echo "$val" | xargs)

    [[ "$type" =~ ^# ]] && continue
    [[ -z "$type" ]] && continue

    if [ "$type" = "alias" ]; then
        ALIASES["$name"]="$val"
    fi
done < "$RULES_FILE"

# Разрешить домен во все IPv4 (A) + IPv6 (AAAA) адреса
resolve_all() {
    local domain=$1 out
    out=$(dig +short "$domain" A 2>/dev/null)
    out="$out
$(dig +short "$domain" AAAA 2>/dev/null)"
    printf '%s' "$out" | awk '$1 != ""'
}

# Активные IP из rules (для безопасной очистки)
declare -A ACTIVE_IPS=()

# 1. Читаем актуальные правила доступа
declare -A CURRENT_RULES
while IFS='|' read -r type src dst || [ -n "$type" ]; do
    type=$(echo "$type" | xargs)
    src=$(echo "$src" | xargs)
    dst=$(echo "$dst" | xargs)

    [[ "$type" =~ ^# ]] && continue
    [[ -z "$type" ]] && continue
    [ "$type" = "alias" ] && continue # Пропускаем строки алиасов

    # Если в качестве назначения указан алиас — заменяем его на реальный порт/протокол
    if [ -n "${ALIASES[$dst]}" ]; then
        dst="${ALIASES[$dst]}"
    fi

    # Генерируем уникальный идентификатор правила для отслеживания изменений
    RULE_KEY="${type}_${src}_${dst}"
    CURRENT_RULES["$RULE_KEY"]=1

    if [ "$src" = "any" ]; then
        IP_LIST="any"
    else
        IP_LIST=$(resolve_all "$src")
        if [ -z "$IP_LIST" ]; then
            IP_LIST="$src"
        fi
    fi

    for IP in $IP_LIST; do
        [ -z "$IP" ] && continue
        ACTIVE_IPS["$IP"]=1

        COMMENT="accesser:[${type}][${src}][${dst}]"

        # Проверяем, существует ли уже точное правило в UFW
        if ufw status verbose | grep -F -q "$COMMENT"; then
            if ufw status verbose | grep -F "$COMMENT" | grep -F -q "$IP"; then
                continue
            fi
        fi

        # Применяем правила
        if [ "$type" = "allow" ]; then
            PORT=$(echo "$dst" | cut -d'/' -f1)
            PROTO=$(echo "$dst" | cut -s -d'/' -f2)
            if [ -n "$PROTO" ]; then
                ufw allow from "$IP" to any port "$PORT" proto "$PROTO" comment "$COMMENT" > /dev/null
            else
                ufw allow from "$IP" to any port "$PORT" comment "$COMMENT" > /dev/null
            fi

        elif [ "$type" = "deny" ]; then
            PORT=$(echo "$dst" | cut -d'/' -f1)
            PROTO=$(echo "$dst" | cut -s -d'/' -f2)
            if [ -n "$PROTO" ]; then
                ufw deny from "$IP" to any port "$PORT" proto "$PROTO" comment "$COMMENT" > /dev/null
            else
                ufw deny from "$IP" to any port "$PORT" comment "$COMMENT" > /dev/null
            fi

        elif [ "$type" = "icmp" ]; then
            ufw allow from "$IP" proto icmp comment "$COMMENT" > /dev/null
        fi
    done
done < "$RULES_FILE"

# 2. Очистка устаревших правил UFW — из rules удалены или IP сменился
ufw status numbered | grep 'comment "accesser:' | tac | while read -r line; do
    CONF_DATA=$(echo "$line" | grep -o 'accesser:.*' | sed 's/accesser://')

    T_TYPE=$(echo "$CONF_DATA" | awk -F'[][]' '{print $2}')
    T_SRC=$(echo "$CONF_DATA" | awk -F'[][]' '{print $4}')
    T_DST=$(echo "$CONF_DATA" | awk -F'[][]' '{print $6}')

    CHECK_KEY="${T_TYPE}_${T_SRC}_${T_DST}"
    NUM=$(echo "$line" | sed -e 's/^\[//' -e 's/\].*//' | xargs)

    if [ -z "${CURRENT_RULES[$CHECK_KEY]}" ]; then
        echo "y" | ufw delete "$NUM" > /dev/null
        continue
    fi

    if [ "$T_SRC" != "any" ]; then
        LIVE_IPS=$(resolve_all "$T_SRC")
        if [ -z "$LIVE_IPS" ]; then LIVE_IPS="$T_SRC"; fi

        UFW_IP=$(echo "$line" | tr -s ' ' | cut -d' ' -f3)
        [ "$UFW_IP" = "Anywhere" ] && UFW_IP="any"

        MATCH=0
        for LIP in $LIVE_IPS; do
            if [ "$UFW_IP" = "$LIP" ] || [ "$T_SRC" = "any" ]; then
                MATCH=1
                break
            fi
        done

        if [ "$MATCH" -eq 0 ]; then
            echo "y" | ufw delete "$NUM" > /dev/null
        fi
    fi
done
EOF

chmod +x "$SCRIPT_FILE"
echo "Создан скрипт синхронизации: $SCRIPT_FILE"

echo "=== 5. Первичный запуск синхронизации ==="
"$SCRIPT_FILE"

echo "=== 6. Настройка планировщика Cron (каждые 5 минут) ==="
CRON_CMD="*/5 * * * * /opt/accesser/update.sh > /dev/null 2>&1"
(crontab -l 2>/dev/null | grep -F -v "$SCRIPT_FILE" ; echo "$CRON_CMD") | crontab -

echo "=== 7. Активация UFW ==="
# Защита: Проверяем, открылся ли определенный порт SSH из файла правил
if ! ufw status | grep -E -q "${SSH_PORT}/tcp|${SSH_PORT}.*ALLOW"; then
    echo "Внимание: В правилах 'rules' не найдено разрешение для вашего SSH порта (${SSH_PORT})!"
    echo "Принудительно открываем порт ${SSH_PORT} как временный резерв, чтобы сессия не рухнула."
    ufw allow ${SSH_PORT}/tcp comment "accesser:backup-ssh"
fi

# Включаем брандмауэр
echo "y" | ufw enable

echo "--------------------------------------------------"
echo "Установка успешно завершена!"
echo "Путь к правилам: $RULES_FILE"
echo "Вы можете использовать текстовые алиасы (ssh, http) в правилах."
echo "Посмотреть статус брандмауэра: ufw status verbose"
echo "--------------------------------------------------"

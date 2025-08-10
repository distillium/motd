#!/bin/bash

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly CONFIG_FILE="/etc/dist-motd.conf"
readonly MOTD_SCRIPT="/etc/update-motd.d/00-dist-motd"
readonly APT_CONF_FILE="/etc/apt/apt.conf.d/99force-ipv4"
readonly CMD_MOTD="/usr/local/bin/motd"
readonly CMD_SETTINGS="/usr/local/bin/motd-set"

readonly BACKUP_ROOT="/opt/motd/complete-backup"
readonly INSTALL_MARKER="/opt/motd/custom_motd_installed"

readonly DIRECTORIES_TO_BACKUP=(
    "/etc/update-motd.d"
    "/etc/pam.d"
    "/etc/ssh"
    "/usr/local/bin"
)

readonly APT_GET="/usr/bin/apt-get"
readonly FIND="/usr/bin/find"
readonly CHMOD="/bin/chmod"
readonly MKDIR="/bin/mkdir"
readonly SYSTEMCTL="/bin/systemctl"
readonly SED="/bin/sed"
readonly GREP="/bin/grep"
readonly LN="/bin/ln"
readonly RM="/bin/rm"
readonly CP="/bin/cp"
readonly MV="/bin/mv"
readonly LS="/bin/ls"
readonly DATE="/bin/date"
readonly TAR="/bin/tar"
readonly RSYNC="/usr/bin/rsync"

log_info() {
    echo "[+] $*" >&2
}

log_warn() {
    echo "[!] Warning: $*" >&2
}

log_error() {
    echo "[!] Error: $*" >&2
}

detect_system_version() {
    SYSTEM_TYPE=""
    SYSTEM_VERSION=""
    
    if [[ -f "/etc/debian_version" ]]; then
        if [[ -f "/etc/os-release" ]]; then
            local os_id
            os_id=$(safe_cmd "${GREP}" "^ID=" /etc/os-release | "${CUT}" -d= -f2 | tr -d '"')
            
            case "${os_id}" in
                "ubuntu")
                    SYSTEM_TYPE="ubuntu"
                    SYSTEM_VERSION=$(safe_cmd "${GREP}" "^VERSION_ID=" /etc/os-release | "${CUT}" -d= -f2 | tr -d '"')
                    ;;
                "debian")
                    SYSTEM_TYPE="debian"
                    SYSTEM_VERSION=$(safe_cmd "${CAT}" /etc/debian_version | "${CUT}" -d. -f1)
                    ;;
                *)
                    if "${GREP}" -qi "ubuntu" /etc/os-release; then
                        SYSTEM_TYPE="ubuntu"
                        SYSTEM_VERSION=$(safe_cmd "${GREP}" "^VERSION_ID=" /etc/os-release | "${CUT}" -d= -f2 | tr -d '"')
                    else
                        SYSTEM_TYPE="debian"
                        SYSTEM_VERSION=$(safe_cmd "${CAT}" /etc/debian_version | "${CUT}" -d. -f1)
                    fi
                    ;;
            esac
        else
            SYSTEM_TYPE="debian"
            SYSTEM_VERSION=$(safe_cmd "${CAT}" /etc/debian_version | "${CUT}" -d. -f1)
        fi
    else
        log_error "Неподдерживаемая система - требуется Debian/Ubuntu"
        exit 1
    fi
    
    log_info "Обнаружена система: ${SYSTEM_TYPE} ${SYSTEM_VERSION}"
}

safe_cmd() {
    local cmd_output
    if cmd_output=$("$@" 2>/dev/null); then
        printf '%s' "${cmd_output}"
    else
        printf 'N/A'
    fi
}

check_backup_exists() {
    [[ -f "${INSTALL_MARKER}" ]] && [[ -d "${BACKUP_ROOT}" ]]
}

create_complete_directory_backup() {
    log_info "Создание полного бэкапа директорий..."
    
    "${MKDIR}" -p "${BACKUP_ROOT}"
    "${CHMOD}" 700 "${BACKUP_ROOT}"
    
    for dir in "${DIRECTORIES_TO_BACKUP[@]}"; do
        if [[ -d "${dir}" ]]; then
            local backup_name=$(echo "${dir}" | "${SED}" 's|/|_|g' | "${SED}" 's|^_||')
            local backup_path="${BACKUP_ROOT}/${backup_name}"
            
            log_info "Создание полного бэкапа директории: ${dir}"
            
            if command -v rsync >/dev/null 2>&1; then
                "${RSYNC}" -a --delete "${dir}/" "${backup_path}/"
            else
                "${RM}" -rf "${backup_path}" 2>/dev/null || true
                "${CP}" -a "${dir}" "${backup_path}"
            fi
            
            log_info "Бэкап сохранен: ${backup_path}"
        else
            log_warn "Не найдена директория для бэкапа: ${dir}"
        fi
    done
    
    local important_files=(
        "/etc/motd"
        "/etc/bash.bashrc"
    )
    
    for file in "${important_files[@]}"; do
        if [[ -f "${file}" ]] || [[ -L "${file}" ]]; then
            local backup_name=$(echo "${file}" | "${SED}" 's|/|_|g' | "${SED}" 's|^_||')
            "${CP}" -a "${file}" "${BACKUP_ROOT}/${backup_name}" 2>/dev/null || true
            log_info "Файл сохранен в бэкап: ${file}"
        fi
    done
    
    "${DATE}" > "${INSTALL_MARKER}"
    
    log_info "Полный бэкап директорий завершен: ${BACKUP_ROOT}"
}

restore_complete_directories() {
    log_info "Полное восстановление директорий из бэкапа..."
    
    if ! check_backup_exists; then
        log_error "Бэкапы не найдены. Невозможно выполнить восстановление."
        return 1
    fi
    
    for dir in "${DIRECTORIES_TO_BACKUP[@]}"; do
        local backup_name=$(echo "${dir}" | "${SED}" 's|/|_|g' | "${SED}" 's|^_||')
        local backup_path="${BACKUP_ROOT}/${backup_name}"
        
        if [[ -d "${backup_path}" ]]; then
            log_info "Восстановление директории: ${dir}"
            
            "${RM}" -rf "${dir}" 2>/dev/null || true
            "${MKDIR}" -p "$(dirname "${dir}")"
            
            if command -v rsync >/dev/null 2>&1; then
                "${RSYNC}" -a --delete "${backup_path}/" "${dir}/"
            else
                "${CP}" -a "${backup_path}" "${dir}"
            fi
            
            log_info "Директория восстановлена: ${dir}"
        else
            log_warn "Бэкап директории не найден: ${backup_path}"
        fi
    done
    
    local important_files=(
        "/etc/motd"
        "/etc/bash.bashrc"
    )
    
    for file in "${important_files[@]}"; do
        local backup_name=$(echo "${file}" | "${SED}" 's|/|_|g' | "${SED}" 's|^_||')
        local backup_file="${BACKUP_ROOT}/${backup_name}"
        
        if [[ -f "${backup_file}" ]] || [[ -L "${backup_file}" ]]; then
            "${RM}" -f "${file}" 2>/dev/null || true
            "${CP}" -a "${backup_file}" "${file}"
            log_info "Файл восстановлен: ${file}"
        fi
    done
    
    log_info "Полное восстановление директорий завершено"
}

complete_cleanup() {
    log_info "Полная очистка всех следов кастомного MOTD..."
    
    local custom_files=(
        "${CONFIG_FILE}"
        "${MOTD_SCRIPT}"
        "${CMD_MOTD}"
        "${CMD_SETTINGS}"
        "${APT_CONF_FILE}"
    )
    
    for file in "${custom_files[@]}"; do
        "${RM}" -f "${file}" 2>/dev/null || true
    done
    
    local cache_files=(
        "/var/run/motd"
        "/var/run/motd.dynamic"
        "/run/motd"
        "/run/motd.dynamic"
        "/var/lib/update-notifier/updates-available"
    )
    
    for cache_file in "${cache_files[@]}"; do
        "${RM}" -f "${cache_file}" 2>/dev/null || true
    done
    
    if "${SYSTEMCTL}" is-active ssh >/dev/null 2>&1; then
        "${SYSTEMCTL}" reload ssh 2>/dev/null || true
    elif "${SYSTEMCTL}" is-active sshd >/dev/null 2>&1; then
        "${SYSTEMCTL}" reload sshd 2>/dev/null || true
    fi
    
    log_info "Полная очистка завершена"
}

force_regenerate_standard_motd() {
    log_info "Принудительная регенерация стандартного MOTD для ${SYSTEM_TYPE} ${SYSTEM_VERSION}..."
    
    local cache_files=(
        "/var/run/motd"
        "/var/run/motd.dynamic"
        "/run/motd"
        "/run/motd.dynamic"
        "/var/lib/update-notifier/updates-available"
    )
    
    for cache_file in "${cache_files[@]}"; do
        "${RM}" -f "${cache_file}" 2>/dev/null || true
    done
    
    if command -v apt >/dev/null 2>&1; then
        apt list --upgradable > /dev/null 2>&1 || true
        
        if [[ -x "/usr/lib/update-notifier/apt-check" ]]; then
            /usr/lib/update-notifier/apt-check 2>&1 | head -1 > /var/lib/update-notifier/updates-available || true
        fi
    fi
    
    if [[ -d "/etc/update-motd.d" ]]; then
        case "${SYSTEM_TYPE}" in
            "ubuntu")
                local ubuntu_major ubuntu_minor
                ubuntu_major=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f1)
                ubuntu_minor=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f2)
                local ubuntu_numeric=$((ubuntu_major * 100 + ubuntu_minor))
                
                if [[ "${ubuntu_numeric}" -ge 2404 ]]; then
                    "${CHMOD}" 755 /etc/update-motd.d/* 2>/dev/null || true
                    "${CHMOD}" 644 /etc/update-motd.d/00-header 2>/dev/null || true
                    "${CHMOD}" 644 /etc/update-motd.d/10-help-text 2>/dev/null || true
                else
                    "${CHMOD}" +x /etc/update-motd.d/* 2>/dev/null || true
                fi
                ;;
            "debian")
                if [[ "${SYSTEM_VERSION}" =~ ^[0-9]+$ ]] && [[ "${SYSTEM_VERSION}" -ge 13 ]]; then
                    "${CHMOD}" 755 /etc/update-motd.d/* 2>/dev/null || true
                else
                    "${CHMOD}" +x /etc/update-motd.d/* 2>/dev/null || true
                fi
                ;;
        esac
        
        "${CHMOD}" -x /etc/update-motd.d/00-dist-motd 2>/dev/null || true
        
        if command -v run-parts >/dev/null 2>&1; then
            local temp_motd=$(mktemp)
            run-parts --lsbsysinit /etc/update-motd.d/ > "${temp_motd}" 2>/dev/null || true
            
            if [[ -s "${temp_motd}" ]]; then
                "${CP}" "${temp_motd}" "/var/run/motd.dynamic"
                "${CHMOD}" 644 "/var/run/motd.dynamic"
                "${CP}" "${temp_motd}" "/run/motd.dynamic" 2>/dev/null || true
            fi
            
            "${RM}" -f "${temp_motd}"
        fi
    fi
    
    case "${SYSTEM_TYPE}" in
        "ubuntu")
            local ubuntu_major ubuntu_minor
            ubuntu_major=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f1)
            ubuntu_minor=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f2)
            local ubuntu_numeric=$((ubuntu_major * 100 + ubuntu_minor))
            
            if [[ "${ubuntu_numeric}" -ge 2404 ]]; then
                if [[ -f "/etc/motd" ]]; then
                    "${CHMOD}" 644 "/etc/motd" 2>/dev/null || true
                fi
            fi
            ;;
    esac
    
    if "${SYSTEMCTL}" list-unit-files | grep -q "motd-news"; then
        "${SYSTEMCTL}" restart motd-news.timer 2>/dev/null || true
    fi
    
    log_info "Регенерация стандартного MOTD завершена"
}

complete_uninstall() {
    log_info "Выполняется полное удаление кастомного MOTD..."
    
    complete_cleanup
    restore_complete_directories
    force_regenerate_standard_motd
    
    "${RM}" -rf "/opt/motd"
    
    log_info "Полное удаление завершено, система восстановлена"
}

cleanup_on_error() {
    log_error "Произошла ошибка во время установки. Выполняется полный откат..."
    
    if check_backup_exists; then
        complete_uninstall
    else
        complete_cleanup
    fi
    
    exit 1
}

trap cleanup_on_error ERR

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "Скрипт должен выполняться с правами суперпользователя"
        exit 1
    fi
}

check_existing_installation() {
    if check_backup_exists; then
        log_warn "Обнаружена существующая установка кастомного MOTD"
        echo "Хотите переустановить? (это полностью удалит текущую установку и создаст новую)"
        
        local response
        if [[ -t 0 ]]; then
            echo -n "Продолжить? [y/N]: "
            read -r response
        else
            echo -n "Продолжить? [y/N]: " > /dev/tty
            read -r response < /dev/tty
        fi
        
        case "${response,,}" in
            y|yes|да|д)
                log_info "Пользователь подтвердил переустановку"
                complete_uninstall
                log_info "Предыдущая установка полностью удалена, продолжаем установку..."
                ;;
            *)
                log_info "Установка отменена пользователем"
                exit 0
                ;;
        esac
    fi
}

validate_system() {
    detect_system_version
    
    case "${SYSTEM_TYPE}" in
        "debian")
            if [[ "${SYSTEM_VERSION}" =~ ^[0-9]+$ ]] && [[ "${SYSTEM_VERSION}" -lt 11 ]]; then
                log_error "Требуется Debian 11 или новее. Обнаружен: Debian ${SYSTEM_VERSION}"
                exit 1
            fi
            ;;
        "ubuntu")
            local ubuntu_major ubuntu_minor
            ubuntu_major=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f1)
            ubuntu_minor=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f2)
            local ubuntu_numeric=$((ubuntu_major * 100 + ubuntu_minor))
            
            if [[ "${ubuntu_numeric}" -lt 2204 ]]; then
                log_error "Требуется Ubuntu 22.04 или новее. Обнаружен: Ubuntu ${SYSTEM_VERSION}"
                exit 1
            fi
            ;;
        *)
            log_error "Неподдерживаемая система. Поддерживаются только Debian 11+ и Ubuntu 22.04+"
            exit 1
            ;;
    esac
    
    local required_commands=("${APT_GET}" "${SED}" "${GREP}" "${CHMOD}" "${TAR}")
    for cmd in "${required_commands[@]}"; do
        if [[ ! -x "${cmd}" ]]; then
            log_error "Команда ${cmd} не найдена или недоступна"
            exit 1
        fi
    done
    
    log_info "Система совместима: ${SYSTEM_TYPE} ${SYSTEM_VERSION}"
}

install_dependencies() {
    log_info "Установка зависимостей для ${SYSTEM_TYPE} ${SYSTEM_VERSION}..."
    
    if [[ ! -f "${APT_CONF_FILE}" ]]; then
        echo 'Acquire::ForceIPv4 "true";' > "${APT_CONF_FILE}"
        "${CHMOD}" 644 "${APT_CONF_FILE}"
    fi
    
    if ! "${APT_GET}" update -qq; then
        log_warn "Не удалось обновить список пакетов, продолжаем установку"
    fi
    
    local packages=("toilet" "figlet" "procps" "lsb-release" "whiptail" "rsync")
    
    case "${SYSTEM_TYPE}" in
        "debian")
            if [[ "${SYSTEM_VERSION}" =~ ^[0-9]+$ ]] && [[ "${SYSTEM_VERSION}" -ge 13 ]]; then
                log_info "Добавляем пакеты для Debian 13+..."
                packages+=("sqlite3")
            fi
            ;;
        "ubuntu")
            local ubuntu_major ubuntu_minor
            ubuntu_major=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f1)
            ubuntu_minor=$(echo "${SYSTEM_VERSION}" | "${CUT}" -d. -f2)
            local ubuntu_numeric=$((ubuntu_major * 100 + ubuntu_minor))
            
            if [[ "${ubuntu_numeric}" -ge 2404 ]]; then
                log_info "Добавляем пакеты для Ubuntu 24.04+..."
                packages+=("sqlite3")
            fi
            ;;
    esac
    
    if ! "${APT_GET}" install -y "${packages[@]}" > /dev/null; then
        log_error "Не удалось установить необходимые пакеты"
        exit 1
    fi
    
    log_info "Зависимости установлены успешно"
}

create_config() {
    log_info "Создание конфигурации MOTD..."
    
    cat > "${CONFIG_FILE}" << 'EOF'
SHOW_LOGO=true
SHOW_CPU=true
SHOW_MEM=true
SHOW_NET=true
SHOW_DOCKER=true
SHOW_FIREWALL=true
SHOW_FIREWALL_RULES=false
SHOW_UPDATES=false
EOF
    
    "${CHMOD}" 644 "${CONFIG_FILE}"
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_error "Не удалось создать конфигурационный файл"
        exit 1
    fi
}

create_motd_script() {
    log_info "Установка скрипта MOTD..."
    
    "${MKDIR}" -p /etc/update-motd.d
    
    cat > "${MOTD_SCRIPT}" << 'MOTD_EOF'
#!/bin/bash

if [[ -f "/etc/dist-motd.conf" ]]; then
    source "/etc/dist-motd.conf"
else
    SHOW_LOGO=true
    SHOW_CPU=true
    SHOW_MEM=true
    SHOW_NET=true
    SHOW_DOCKER=true
    SHOW_FIREWALL=true
    SHOW_FIREWALL_RULES=false
fi

readonly COLOR_TITLE="\e[1;37m"
readonly COLOR_LABEL="\e[0;36m"
readonly COLOR_VALUE="\e[0;37m"
readonly COLOR_GREEN="\e[0;32m"
readonly COLOR_RED="\e[0;31m"
readonly COLOR_YELLOW="\e[0;33m"
readonly BOLD="\e[1m"
readonly RESET="\e[0m"

readonly TOILET="/usr/bin/toilet"
readonly LAST="/usr/bin/last"
readonly LASTLOG="/usr/bin/lastlog"
readonly WHO="/usr/bin/who"
readonly UPTIME="/usr/bin/uptime"
readonly HOSTNAME="/bin/hostname"
readonly LSB_RELEASE="/usr/bin/lsb-release"
readonly IP="/sbin/ip"
readonly UNAME="/bin/uname"
readonly VMSTAT="/usr/bin/vmstat"
readonly FREE="/usr/bin/free"
readonly DF="/bin/df"
readonly CAT="/bin/cat"
readonly AWK="/usr/bin/awk"
readonly CUT="/usr/bin/cut"
readonly HEAD="/usr/bin/head"
readonly TAIL="/usr/bin/tail"
readonly GREP="/bin/grep"
readonly SED="/bin/sed"
readonly DOCKER="/usr/bin/docker"
readonly WC="/usr/bin/wc"

bar() {
    local used=$1
    local total=$2
    local width=30
    
    if [[ ! "${used}" =~ ^[0-9]+$ ]] || [[ ! "${total}" =~ ^[0-9]+$ ]] || [[ "${total}" -eq 0 ]]; then
        printf "[%-${width}s] N/A" ""
        return
    fi
    
    local percent=$((100 * used / total))
    local filled=$((width * used / total))
    local empty=$((width - filled))
    local color
    
    if [[ "${percent}" -lt 50 ]]; then 
        color="${COLOR_GREEN}"
    elif [[ "${percent}" -lt 80 ]]; then 
        color="${COLOR_YELLOW}"
    else 
        color="${COLOR_RED}"
    fi
    
    printf "["
    for ((i=0; i<filled; i++)); do printf "${color}━"; done
    for ((i=0; i<empty; i++)); do printf "${RESET}━"; done
    printf "${RESET}] %d%%" "${percent}"
}

safe_cmd() {
    local cmd_output
    if cmd_output=$("$@" 2>/dev/null); then
        printf '%s' "${cmd_output}"
    else
        printf 'N/A'
    fi
}

show_logo() {
    if [[ "${SHOW_LOGO}" = "true" ]] && [[ -x "${TOILET}" ]]; then
        echo -e "${COLOR_TITLE}"
        "${TOILET}" -f standard "distillium" 2>/dev/null || echo "distillium"
        echo -e "${RESET}"
    fi
}

show_session_info() {
    echo -e "${COLOR_TITLE}• Session Info${RESET}"
    
    local real_user
    real_user=$(safe_cmd /usr/bin/logname)
    if [[ "${real_user}" = "N/A" ]]; then
        real_user=$(safe_cmd "${WHO}" | "${AWK}" 'NR==1{print $1}')
    fi
    printf "${COLOR_LABEL}%-22s${COLOR_YELLOW}%s${RESET}\n" "User:" "${real_user:-Unknown}"
    
    local lastlog_displayed=false
    
    if command -v lastlog2 >/dev/null 2>&1; then
        local lastlog2_output
        lastlog2_output=$(safe_cmd lastlog2 show -u "${real_user}" 2>/dev/null | "${TAIL}" -n 1)
        if [[ "${lastlog2_output}" != "N/A" ]] && [[ "${lastlog2_output}" != *"Never logged in"* ]] && [[ -n "${lastlog2_output}" ]]; then
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Last login:" "${lastlog2_output}"
            lastlog_displayed=true
        fi
    fi
    
    if [[ "${lastlog_displayed}" = false ]] && [[ -f "/var/lib/wtmpdb/wtmp.db" ]] && command -v sqlite3 >/dev/null 2>&1; then
        local wtmp_query
        wtmp_query=$(safe_cmd sqlite3 /var/lib/wtmpdb/wtmp.db "SELECT strftime('%Y-%m-%d %H:%M:%S', time, 'unixepoch'), host FROM wtmp WHERE user='${real_user}' AND type=7 ORDER BY time DESC LIMIT 1;" 2>/dev/null)
        if [[ "${wtmp_query}" != "N/A" ]] && [[ -n "${wtmp_query}" ]]; then
            local wtmp_time wtmp_host
            wtmp_time=$(echo "${wtmp_query}" | "${CUT}" -d'|' -f1)
            wtmp_host=$(echo "${wtmp_query}" | "${CUT}" -d'|' -f2)
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s ${COLOR_YELLOW}from %s${RESET}\n" "Last login:" "${wtmp_time}" "${wtmp_host:-unknown}"
            lastlog_displayed=true
        fi
    fi
    
    if [[ "${lastlog_displayed}" = false ]] && [[ -f "/var/log/lastlog" ]] && [[ -x "${LASTLOG}" ]]; then
        local lastlog_raw lastlog_date lastlog_ip
        lastlog_raw=$(safe_cmd "${LASTLOG}" -u "${real_user}" | "${TAIL}" -n 1)
        if [[ "${lastlog_raw}" != "N/A" ]] && [[ "${lastlog_raw}" != *"Never logged in"* ]]; then
            lastlog_date=$(echo "${lastlog_raw}" | "${AWK}" '{printf "%s %s %s %s %s", $4, $5, $6, $7, $9}')
            lastlog_ip=$(echo "${lastlog_raw}" | "${AWK}" '{print $3}')
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s ${COLOR_YELLOW}from %s${RESET}\n" "Last login:" "${lastlog_date}" "${lastlog_ip}"
            lastlog_displayed=true
        fi
    fi
    
    if [[ "${lastlog_displayed}" = false ]]; then
        echo -e "${COLOR_LABEL}Last login:${RESET} not available"
    fi
    
    local uptime_fmt
    uptime_fmt=$(safe_cmd "${UPTIME}" -p | "${SED}" 's/up //')
    printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Uptime:" "${uptime_fmt:-Unknown}"
}

show_system_info() {
    echo -e "\n${COLOR_TITLE}• System Info${RESET}"
    
    local hostname_value
    hostname_value=$(safe_cmd "${HOSTNAME}")
    printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Hostname:" "${hostname_value:-Unknown}"
    
    local os_info
    if [[ -x "${LSB_RELEASE}" ]]; then
        os_info=$(safe_cmd "${LSB_RELEASE}" -ds)
    elif [[ -f "/etc/os-release" ]]; then
        os_info=$(safe_cmd "${GREP}" PRETTY_NAME /etc/os-release | "${CUT}" -d= -f2 | tr -d '"')
    else
        os_info="Unknown"
    fi
    printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "OS:" "${os_info}"
    
    local ipv4 ipv6
    if [[ -x "${IP}" ]]; then
        ipv4=$(safe_cmd "${IP}" -4 addr show scope global | "${AWK}" '/inet/ {print $2}' | "${CUT}" -d/ -f1 | "${HEAD}" -n1)
        ipv6=$(safe_cmd "${IP}" -6 addr show scope global | "${AWK}" '/inet6/ {print $2}' | "${CUT}" -d/ -f1 | "${HEAD}" -n1)
    fi
    printf "${COLOR_LABEL}%-22s${COLOR_YELLOW}%s${RESET}\n" "External IP (v4):" "${ipv4:-N/A}"
    printf "${COLOR_LABEL}%-22s${COLOR_YELLOW}%s${RESET}\n" "External IP (v6):" "${ipv6:-N/A}"
    
    local kernel_version
    kernel_version=$(safe_cmd "${UNAME}" -r)
    printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Kernel:" "${kernel_version:-Unknown}"
}

show_cpu_info() {
    if [[ "${SHOW_CPU}" = "true" ]]; then
        echo -e "\n${COLOR_TITLE}• CPU${RESET}"
        
        local cpu_model
        if [[ -f "/proc/cpuinfo" ]]; then
            cpu_model=$(safe_cmd "${GREP}" -m1 "model name" /proc/cpuinfo | "${CUT}" -d ':' -f2 | "${SED}" 's/^ //')
        fi
        printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Model:" "${cpu_model:-Unknown}"
        
        local cpu_idle cpu_usage
        if [[ -x "${VMSTAT}" ]]; then
            cpu_idle=$(safe_cmd "${VMSTAT}" 1 2 | "${TAIL}" -1 | "${AWK}" '{print $15}')
            if [[ "${cpu_idle}" =~ ^[0-9]+$ ]]; then
                cpu_usage=$((100 - cpu_idle))
            else
                cpu_usage="N/A"
            fi
        else
            cpu_usage="N/A"
        fi
        
        printf "${COLOR_LABEL}%-22s" "Usage:"
        if [[ "${cpu_usage}" != "N/A" ]]; then
            bar "${cpu_usage}" 100
        else
            printf "N/A"
        fi
        echo
        
        local load_avg
        if [[ -f "/proc/loadavg" ]]; then
            load_avg=$(safe_cmd "${AWK}" '{print $1 " / " $2 " / " $3}' /proc/loadavg)
        fi
        printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Load average:" "${load_avg:-Unknown}"
    fi
}

show_memory_info() {
    if [[ "${SHOW_MEM}" = "true" ]]; then
        echo -e "\n${COLOR_TITLE}• RAM & Disk${RESET}"
        
        if [[ -x "${FREE}" ]]; then
            local mem_total mem_used
            mem_total=$(safe_cmd "${FREE}" -m | "${AWK}" '/Mem:/ {print $2}')
            mem_used=$(safe_cmd "${FREE}" -m | "${AWK}" '/Mem:/ {print $3}')
            
            printf "${COLOR_LABEL}%-22s" "RAM:"
            if [[ "${mem_total}" =~ ^[0-9]+$ ]] && [[ "${mem_used}" =~ ^[0-9]+$ ]]; then
                bar "${mem_used}" "${mem_total}"
            else
                printf "N/A"
            fi
            echo
        fi
        
        if [[ -x "${DF}" ]]; then
            local disk_used disk_total
            disk_used=$(safe_cmd "${DF}" -m / | "${AWK}" 'NR==2{print $3}')
            disk_total=$(safe_cmd "${DF}" -m / | "${AWK}" 'NR==2{print $2}')
            
            printf "${COLOR_LABEL}%-22s" "Disk:"
            if [[ "${disk_used}" =~ ^[0-9]+$ ]] && [[ "${disk_total}" =~ ^[0-9]+$ ]]; then
                bar "${disk_used}" "${disk_total}"
            else
                printf "N/A"
            fi
            echo
        fi
    fi
}

show_network_info() {
    if [[ "${SHOW_NET}" = "true" ]] && [[ -x "${IP}" ]]; then
        echo -e "\n${COLOR_TITLE}• Network${RESET}"
        
        local net_iface
        net_iface=$(safe_cmd "${IP}" route get 8.8.8.8 2>/dev/null | "${AWK}" '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
        
        if [[ -n "${net_iface}" ]] && [[ -f "/sys/class/net/${net_iface}/statistics/rx_bytes" ]]; then
            local rx_bytes tx_bytes
            rx_bytes=$(safe_cmd "${CAT}" "/sys/class/net/${net_iface}/statistics/rx_bytes")
            tx_bytes=$(safe_cmd "${CAT}" "/sys/class/net/${net_iface}/statistics/tx_bytes")
            
            human_readable() {
                local bytes=$1
                local units=('B' 'KB' 'MB' 'GB' 'TB') 
                local unit=0
                
                if [[ ! "${bytes}" =~ ^[0-9]+$ ]]; then
                    echo "N/A"
                    return
                fi
                
                while (( bytes > 1024 && unit < 4 )); do 
                    bytes=$((bytes / 1024))
                    ((unit++))
                done
                echo "${bytes} ${units[$unit]}"
            }
            
            local rx_hr tx_hr
            rx_hr=$(human_readable "${rx_bytes}")
            tx_hr=$(human_readable "${tx_bytes}")
            
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Interface:" "${net_iface}"
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Received:" "${rx_hr}"
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Transmitted:" "${tx_hr}"
        else
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Network:" "Interface not found"
        fi
    fi
}

show_firewall_info() {
    if [[ "${SHOW_FIREWALL}" = "true" ]]; then
        echo -e "\n${COLOR_TITLE}• Firewall${RESET}"
        
        local ufw_bin="/usr/sbin/ufw"
        if [[ -x "${ufw_bin}" ]]; then
            local status
            status=$(safe_cmd "${ufw_bin}" status | "${HEAD}" -1 | "${AWK}" '{print $2}')
            
            if [[ "${status}" = "active" ]]; then
                printf "${COLOR_LABEL}%-22s${COLOR_GREEN}%s${RESET}\n" "UFW Status:" "${status}"
                
                if [[ "${SHOW_FIREWALL_RULES}" = "true" ]]; then
                    local rules_output
                    if rules_output=$(safe_cmd "${ufw_bin}" status 2>/dev/null); then
                        local rules_array
                        mapfile -t rules_array < <(echo "${rules_output}" | "${AWK}" '/ALLOW/ {
                            port=$1
                            from=""
                            for (i=3; i<=NF; i++) {
                                if ($i != "ALLOW") from=from $i " "
                            }
                            gsub(/[[:space:]]+$/, "", from)
                            sub(/#.*/, "", from)
                            gsub(/[[:space:]]+$/, "", from)
                            
                            if (port ~ /\(v6\)/) {
                                sub(/ \(v6\)/, "", port)
                                if (from == "Anywhere") from = "Anywhere (v6)"
                            }
                            
                            print port "|" from
                        }')
                        
                        if [[ ${#rules_array[@]} -gt 0 ]]; then
                            declare -A grouped_rules
                            for rule in "${rules_array[@]}"; do
                                local port="${rule%%|*}"
                                local from="${rule##*|}"
                                grouped_rules["${from}"]+="${port}, "
                            done
                            
                            echo -e "${COLOR_LABEL}Rules:${RESET}"
                            for from in "${!grouped_rules[@]}"; do
                                local ports="${grouped_rules[${from}]}"
                                ports="${ports%, }"
                                echo -e "  ${COLOR_VALUE}${ports} ALLOW from ${from}${RESET}"
                            done
                        else
                            echo -e "${COLOR_LABEL}Rules:${RESET} None"
                        fi
                    fi
                fi
            else
                printf "${COLOR_LABEL}%-22s${COLOR_RED}%s${RESET}\n" "UFW Status:" "${status:-inactive}"
            fi
        else
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "UFW:" "not installed"
        fi
    fi
}

show_docker_info() {
    if [[ "${SHOW_DOCKER}" = "true" ]] && [[ -x "${DOCKER}" ]]; then
        echo -e "\n${COLOR_TITLE}• Docker${RESET}"
        
        local running_names_output total_names_output
        running_names_output=$(safe_cmd "${DOCKER}" ps --format '{{.Names}}' 2>/dev/null)
        total_names_output=$(safe_cmd "${DOCKER}" ps -a --format '{{.Names}}' 2>/dev/null)
        
        local running_count=0 total_count=0
        
        if [[ "${running_names_output}" != "N/A" ]] && [[ -n "${running_names_output}" ]]; then
            running_count=$(echo "${running_names_output}" | "${WC}" -l)
        fi
        
        if [[ "${total_names_output}" != "N/A" ]] && [[ -n "${total_names_output}" ]]; then
            total_count=$(echo "${total_names_output}" | "${WC}" -l)
        fi
        
        printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Containers:" "${running_count} / ${total_count}"
        
        if [[ "${running_count}" -gt 0 ]] && [[ "${running_names_output}" != "N/A" ]]; then
            echo -e "${COLOR_LABEL}Running Containers:${RESET}"
            
            local names_array=()
            while IFS= read -r line; do
                [[ -n "$line" ]] && names_array+=("$line")
            done <<< "${running_names_output}"
            
            for ((i = 0; i < ${#names_array[@]}; i+=2)); do
                if [[ $((i + 1)) -lt ${#names_array[@]} ]]; then
                    printf "  ${COLOR_VALUE}%-30s%-30s${RESET}\n" "${names_array[$i]}" "${names_array[$((i + 1))]}"
                else
                    printf "  ${COLOR_VALUE}%-30s${RESET}\n" "${names_array[$i]}"
                fi
            done
        fi
    elif [[ "${SHOW_DOCKER}" = "true" ]]; then
        echo -e "\n${COLOR_TITLE}• Docker${RESET}"
        printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Docker:" "not installed"
    fi
}

show_updates_info() {
    if [[ "${SHOW_UPDATES}" = "true" ]]; then
        echo -e "\n${COLOR_TITLE}• Updates Available${RESET}"
        
        local updates_count security_count
        
        if command -v apt >/dev/null 2>&1; then
            updates_count=$(safe_cmd apt list --upgradable 2>/dev/null | "${GREP}" -v "Listing" | "${WC}" -l)
            
            if [[ "${updates_count}" =~ ^[0-9]+$ ]] && [[ "${updates_count}" -gt 0 ]]; then
                printf "${COLOR_LABEL}%-22s${COLOR_YELLOW}%s packages${RESET}\n" "Total updates:" "${updates_count}"
                
                if [[ -x "/usr/lib/update-notifier/apt-check" ]]; then
                    local apt_check_output
                    apt_check_output=$(safe_cmd /usr/lib/update-notifier/apt-check 2>&1)
                    security_count=$(echo "${apt_check_output}" | "${CUT}" -d';' -f2)
                    
                    if [[ "${security_count}" =~ ^[0-9]+$ ]] && [[ "${security_count}" -gt 0 ]]; then
                        printf "${COLOR_LABEL}%-22s${COLOR_RED}%s security${RESET}\n" "Security updates:" "${security_count}"
                    fi
                fi
                
                echo -e "${COLOR_LABEL}Run 'sudo apt upgrade' to install updates${RESET}"
            else
                printf "${COLOR_LABEL}%-22s${COLOR_GREEN}%s${RESET}\n" "Status:" "System is up to date"
            fi
        else
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Updates:" "apt not available"
        fi
    fi
}


main() {
    show_logo
    show_session_info
    show_system_info
    show_cpu_info
    show_memory_info
    show_network_info
    show_firewall_info
    show_docker_info
    show_updates_info 
    echo
}

if main; then
    exit 0
else
    echo -e "${COLOR_RED}Ошибка при выполнении MOTD скрипта${RESET}" >&2
    exit 1
fi
MOTD_EOF

    "${CHMOD}" 755 "${MOTD_SCRIPT}"
    
    if [[ ! -x "${MOTD_SCRIPT}" ]]; then
        log_error "Не удалось создать исполняемый MOTD скрипт"
        exit 1
    fi
}

create_settings_command() {
    log_info "Создание меню конфигурации motd-set..."
    
    cat > "${CMD_SETTINGS}" << 'SETTINGS_EOF'
#!/bin/bash

readonly CONFIG="/etc/dist-motd.conf"
readonly WHIPTAIL="/usr/bin/whiptail"
readonly BACKUP_ROOT="/opt/motd/complete-backup"
readonly INSTALL_MARKER="/opt/motd/custom_motd_installed"

readonly DIRECTORIES_TO_BACKUP=(
    "/etc/update-motd.d"
    "/etc/pam.d"
    "/etc/ssh"
    "/usr/local/bin"
)

check_backup_exists() {
    [[ -f "${INSTALL_MARKER}" ]] && [[ -d "${BACKUP_ROOT}" ]]
}

restore_complete_directories() {
    echo "[+] Полное восстановление директорий из бэкапа..."
    
    if ! check_backup_exists; then
        echo "[!] Бэкапы не найдены."
        return 1
    fi
    
    for dir in "${DIRECTORIES_TO_BACKUP[@]}"; do
        local backup_name=$(echo "${dir}" | /bin/sed 's|/|_|g' | /bin/sed 's|^_||')
        local backup_path="${BACKUP_ROOT}/${backup_name}"
        
        if [[ -d "${backup_path}" ]]; then
            echo "[+] Восстановление директории: ${dir}"
            /bin/rm -rf "${dir}" 2>/dev/null || true
            /bin/mkdir -p "$(dirname "${dir}")"
            
            if command -v rsync >/dev/null 2>&1; then
                /usr/bin/rsync -a --delete "${backup_path}/" "${dir}/"
            else
                /bin/cp -a "${backup_path}" "${dir}"
            fi
            
            echo "[+] Директория восстановлена: ${dir}"
        fi
    done
    
    local important_files=("/etc/motd" "/etc/bash.bashrc")
    for file in "${important_files[@]}"; do
        local backup_name=$(echo "${file}" | /bin/sed 's|/|_|g' | /bin/sed 's|^_||')
        local backup_file="${BACKUP_ROOT}/${backup_name}"
        
        if [[ -f "${backup_file}" ]] || [[ -L "${backup_file}" ]]; then
            /bin/rm -f "${file}" 2>/dev/null || true
            /bin/cp -a "${backup_file}" "${file}"
            echo "[+] Файл восстановлен: ${file}"
        fi
    done
    
    echo "[+] Восстановление завершено"
}

force_regenerate_standard_motd() {
    echo "[+] Регенерация стандартного MOTD..."
    
    local cache_files=("/var/run/motd" "/var/run/motd.dynamic" "/run/motd" "/run/motd.dynamic")
    for cache_file in "${cache_files[@]}"; do
        /bin/rm -f "${cache_file}" 2>/dev/null || true
    done
    
    if command -v apt >/dev/null 2>&1; then
        apt list --upgradable > /dev/null 2>&1 || true
        if [[ -x "/usr/lib/update-notifier/apt-check" ]]; then
            /usr/lib/update-notifier/apt-check 2>&1 | head -1 > /var/lib/update-notifier/updates-available || true
        fi
    fi
    
    if [[ -d "/etc/update-motd.d" ]]; then
        if command -v run-parts >/dev/null 2>&1; then
            local temp_motd=$(mktemp)
            run-parts --lsbsysinit /etc/update-motd.d/ > "${temp_motd}" 2>/dev/null || true
            
            if [[ -s "${temp_motd}" ]]; then
                /bin/cp "${temp_motd}" "/var/run/motd.dynamic"
                /bin/chmod 644 "/var/run/motd.dynamic"
                /bin/cp "${temp_motd}" "/run/motd.dynamic" 2>/dev/null || true
            fi
            /bin/rm -f "${temp_motd}"
        fi
    fi
    
    echo "[+] Регенерация завершена"
}

complete_cleanup() {
    echo "[+] Полная очистка кастомного MOTD..."
    
    local custom_files=(
        "/etc/dist-motd.conf"
        "/etc/update-motd.d/00-dist-motd"
        "/usr/local/bin/motd"
        "/usr/local/bin/motd-set"
        "/etc/apt/apt.conf.d/99force-ipv4"
    )
    
    for file in "${custom_files[@]}"; do
        /bin/rm -f "${file}" 2>/dev/null || true
    done
    
    local cache_files=("/var/run/motd" "/var/run/motd.dynamic" "/run/motd" "/run/motd.dynamic")
    for cache_file in "${cache_files[@]}"; do
        /bin/rm -f "${cache_file}" 2>/dev/null || true
    done
}

uninstall_custom_motd() {
    echo "[+] Удаление кастомного MOTD..."
    
    complete_cleanup
    restore_complete_directories
    force_regenerate_standard_motd
    
    if /bin/systemctl is-active ssh >/dev/null 2>&1; then
        /bin/systemctl reload ssh 2>/dev/null || true
    elif /bin/systemctl is-active sshd >/dev/null 2>&1; then
        /bin/systemctl reload sshd 2>/dev/null || true
    fi
    
    /bin/rm -rf "/opt/motd"
    echo "[+] Система полностью восстановлена"
}

check_setting() {
    local setting="$1"
    if /bin/grep -q "${setting}=true" "${CONFIG}" 2>/dev/null; then
        echo "ON"
    else
        echo "OFF"
    fi
}

show_main_menu() {
    while true; do
        CHOICE=$("${WHIPTAIL}" --title "MOTD Management" --menu \
        "Выберите действие:" 15 60 4 \
        "1" "Настроить отображение MOTD" \
        "2" "Удалить кастомный MOTD (с полным восстановлением)" \
        "3" "Показать статус установки" \
        "4" "Выход" \
        3>&1 1>&2 2>&3)
        
        case $CHOICE in
            1) configure_motd_display ;;
            2) confirm_uninstall ;;
            3) show_installation_status ;;
            4) exit 0 ;;
            *) exit 0 ;;
        esac
    done
}

configure_motd_display() {
    if [[ ! -f "${CONFIG}" ]]; then
        "${WHIPTAIL}" --title "Ошибка" --msgbox "Конфигурационный файл не найден: ${CONFIG}" 8 60
        return
    fi
    
    CHOICES=$("${WHIPTAIL}" --title "MOTD Display Settings" --checklist \
    "Выберите, что отображать в MOTD:" 20 70 10 \
    "SHOW_LOGO" "Логотип distillium" "$(check_setting 'SHOW_LOGO')" \
    "SHOW_CPU" "Загрузка процессора" "$(check_setting 'SHOW_CPU')" \
    "SHOW_MEM" "Память и диск" "$(check_setting 'SHOW_MEM')" \
    "SHOW_NET" "Сетевой трафик" "$(check_setting 'SHOW_NET')" \
    "SHOW_FIREWALL" "Статус UFW" "$(check_setting 'SHOW_FIREWALL')" \
    "SHOW_FIREWALL_RULES" "Показать правила UFW" "$(check_setting 'SHOW_FIREWALL_RULES')" \
    "SHOW_DOCKER" "Контейнеры Docker" "$(check_setting 'SHOW_DOCKER')" \
    "SHOW_UPDATES" "Доступные обновления" "$(check_setting 'SHOW_UPDATES')" \
    3>&1 1>&2 2>&3)
    
    if [[ $? -eq 0 ]]; then
        local VARIABLES=("SHOW_LOGO" "SHOW_CPU" "SHOW_MEM" "SHOW_NET" "SHOW_FIREWALL" "SHOW_FIREWALL_RULES" "SHOW_DOCKER" "SHOW_UPDATES")
        
        for var in "${VARIABLES[@]}"; do
            if echo "${CHOICES}" | /bin/grep -q "${var}"; then
                /bin/sed -i "s/^${var}=.*/${var}=true/" "${CONFIG}"
            else
                /bin/sed -i "s/^${var}=.*/${var}=false/" "${CONFIG}"
            fi
        done
        
        "${WHIPTAIL}" --title "Успех" --msgbox "Настройки обновлены!\n\nПроверьте результат командой: motd" 10 50
    fi
}

confirm_uninstall() {
    if ! check_backup_exists; then
        "${WHIPTAIL}" --title "Ошибка" --msgbox "Бэкапы не найдены!\nУдаление невозможно." 10 60
        return
    fi
    
    if "${WHIPTAIL}" --title "Подтверждение удаления" --yesno \
    "ВНИМАНИЕ!\n\nЭто действие полностью удалит кастомный MOTD и восстановит систему из полного бэкапа директорий.\n\nВы уверены?" 12 70; then
        
        (
            echo "10"; echo "Очистка кастомных файлов..."
            sleep 1
            echo "40"; echo "Восстановление директорий..."
            sleep 1
            echo "70"; echo "Регенерация MOTD..."
            sleep 1
            echo "90"; echo "Перезапуск служб..."
            sleep 1
            echo "100"; echo "Завершение..."
            sleep 1
        ) | "${WHIPTAIL}" --title "Удаление MOTD" --gauge "Выполняется полное удаление..." 8 60 0
        
        if uninstall_custom_motd >/dev/null 2>&1; then
            "${WHIPTAIL}" --title "Успех" --msgbox "Кастомный MOTD полностью удален!\n\nСистема восстановлена из полного бэкапа." 10 50
            exit 0
        else
            "${WHIPTAIL}" --title "Ошибка" --msgbox "Произошла ошибка при удалении!" 8 50
        fi
    fi
}

show_installation_status() {
    local status_info=""
    
    if check_backup_exists; then
        status_info+="✓ Кастомный MOTD установлен\n"
        status_info+="✓ Полные бэкапы директорий: ${BACKUP_ROOT}\n"
        
        if [[ -f "${CONFIG}" ]]; then
            status_info+="✓ Конфигурационный файл: ${CONFIG}\n"
        else
            status_info+="✗ Конфигурационный файл отсутствует\n"
        fi
        
        if [[ -x "/etc/update-motd.d/00-dist-motd" ]]; then
            status_info+="✓ MOTD скрипт активен\n"
        else
            status_info+="✗ MOTD скрипт неактивен\n"
        fi
        
        if [[ -f "${INSTALL_MARKER}" ]]; then
            local install_date
            install_date=$(cat "${INSTALL_MARKER}")
            status_info+="📅 Установлен: ${install_date}\n"
        fi
        
    else
        status_info+="✗ Кастомный MOTD не установлен\n"
        status_info+="✗ Бэкапы не найдены\n"
    fi
    
    "${WHIPTAIL}" --title "Статус установки" --msgbox "${status_info}" 15 70
}

if [[ "${EUID}" -ne 0 ]]; then
    "${WHIPTAIL}" --title "Ошибка доступа" --msgbox "Требуются права суперпользователя.\n\nЗапустите с sudo." 8 50
    exit 1
fi

if [[ ! -x "${WHIPTAIL}" ]]; then
    echo "whiptail не установлен" >&2
    exit 1
fi

show_main_menu
SETTINGS_EOF

    "${CHMOD}" 755 "${CMD_SETTINGS}"
    
    if [[ ! -x "${CMD_SETTINGS}" ]]; then
        log_error "Не удалось создать команду настройки"
        exit 1
    fi
}

create_motd_command() {
    log_info "Создание команды запуска MOTD..."
    
    cat > "${CMD_MOTD}" << 'CMD_EOF'
#!/bin/bash

readonly MOTD_SCRIPT="/etc/update-motd.d/00-dist-motd"

if [[ -x "${MOTD_SCRIPT}" ]]; then
    "${MOTD_SCRIPT}"
else
    echo "MOTD скрипт не найден или недоступен" >&2
    exit 1
fi
CMD_EOF

    "${CHMOD}" 755 "${CMD_MOTD}"
    
    if [[ ! -x "${CMD_MOTD}" ]]; then
        log_error "Не удалось создать команду запуска MOTD"
        exit 1
    fi
}

configure_pam_ssh() {
    log_info "Настройка PAM и SSH для MOTD..."
    
    local pam_files=("/etc/pam.d/sshd" "/etc/pam.d/login")
    for pam_file in "${pam_files[@]}"; do
        if [[ -f "${pam_file}" ]]; then
            if ! "${GREP}" -q "session optional pam_motd.so noupdate" "${pam_file}"; then
                echo "session optional pam_motd.so noupdate" >> "${pam_file}"
            fi
        fi
    done
    
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "${sshd_config}" ]]; then
        if "${GREP}" -q "^PrintMotd" "${sshd_config}"; then
            "${SED}" -i 's/^PrintMotd.*/PrintMotd no/' "${sshd_config}"
        else
            echo "PrintMotd no" >> "${sshd_config}"
        fi
        
        if "${GREP}" -q "^PrintLastLog" "${sshd_config}"; then
            "${SED}" -i 's/^PrintLastLog.*/PrintLastLog no/' "${sshd_config}"
        else
            echo "PrintLastLog no" >> "${sshd_config}"
        fi
    fi
    
    for pam_file in "${pam_files[@]}"; do
        if [[ -f "${pam_file}" ]]; then
            "${SED}" -i 's/^\(session.*pam_lastlog.so.*\)/#\1/' "${pam_file}"
        fi
    done
}

restart_ssh_service() {
    local ssh_restarted=false
    
    if "${SYSTEMCTL}" is-active ssh >/dev/null 2>&1; then
        if "${SYSTEMCTL}" reload ssh; then
            ssh_restarted=true
        fi
    elif "${SYSTEMCTL}" is-active sshd >/dev/null 2>&1; then
        if "${SYSTEMCTL}" reload sshd; then
            ssh_restarted=true
        fi
    fi
    
    if [[ "${ssh_restarted}" = false ]]; then
        log_warn "Не удалось перезапустить SSH"
    fi
}

finalize_setup() {
    log_info "Завершаем настройку..."
    
    "${SED}" -i 's|^#\s*\(session\s\+optional\s\+pam_motd\.so\s\+motd=/run/motd\.dynamic\)|\1|' /etc/pam.d/sshd 2>/dev/null || true
    "${SED}" -i 's|^#\s*\(session\s\+optional\s\+pam_motd\.so\s\+noupdate\)|\1|' /etc/pam.d/sshd 2>/dev/null || true
    
    "${CHMOD}" -x /etc/update-motd.d/* 2>/dev/null || true
    "${CHMOD}" +x "${MOTD_SCRIPT}"
    
    "${RM}" -f /etc/motd 2>/dev/null || true
    "${LN}" -sf /var/run/motd /etc/motd 2>/dev/null || true
}

main() {
    log_info "Начинается установка кастомного MOTD с полным бэкапом директорий..."
    
    check_root
    detect_system_version
    check_existing_installation
    validate_system
    
    create_complete_directory_backup
    
    install_dependencies
    create_config
    create_motd_script
    create_settings_command
    create_motd_command
    configure_pam_ssh
    restart_ssh_service
    finalize_setup
    
    log_info "Установка завершена успешно!"
    echo ""
    echo "========================================================="
    echo "             🎉 Кастомный MOTD установлен!"
    echo "========================================================="
    echo ""
    echo "📋 Доступные команды:"
    echo "  • motd         - Показать MOTD"
    echo "  • motd-set     - Настройки и управление"
    echo ""
    echo "💾 Полные бэкапы директорий: ${BACKUP_ROOT}"
    echo "🔄 Для удаления: motd-set -> Удалить"
    echo ""
}

main "$@"

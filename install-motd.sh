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
    log_info "Принудительная регенерация стандартного MOTD..."
    
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
                "${CP}" "${temp_motd}" "/var/run/motd.dynamic"
                "${CHMOD}" 644 "/var/run/motd.dynamic"
                "${CP}" "${temp_motd}" "/run/motd.dynamic" 2>/dev/null || true
            fi
            
            "${RM}" -f "${temp_motd}"
        fi
    fi
    
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
    if [[ ! -f "/etc/debian_version" ]]; then
        log_error "Скрипт предназначен только для систем Debian/Ubuntu"
        exit 1
    fi
    
    local required_commands=("${APT_GET}" "${SED}" "${GREP}" "${CHMOD}" "${TAR}")
    for cmd in "${required_commands[@]}"; do
        if [[ ! -x "${cmd}" ]]; then
            log_error "Команда ${cmd} не найдена или недоступна"
            exit 1
        fi
    done
}

install_dependencies() {
    log_info "Установка зависимостей..."
    
    if [[ ! -f "${APT_CONF_FILE}" ]]; then
        echo 'Acquire::ForceIPv4 "true";' > "${APT_CONF_FILE}"
        "${CHMOD}" 644 "${APT_CONF_FILE}"
    fi
    
    if ! "${APT_GET}" update -qq; then
        log_warn "Не удалось обновить список пакетов, продолжаем установку"
    fi
    
    local packages=("procps" "lsb-release" "whiptail" "rsync")
    if ! "${APT_GET}" install -y "${packages[@]}" > /dev/null; then
        log_error "Не удалось установить необходимые пакеты"
        exit 1
    fi
}

create_config() {
    log_info "Создание конфигурации MOTD..."
    
    cat > "${CONFIG_FILE}" << 'EOF'
SHOW_LOGO=true
SHOW_CPU=true
SHOW_MEM=true
SHOW_NET=false
SHOW_DOCKER=true
SHOW_DOCKER_STATUS=true
SHOW_DOCKER_RUNNING_LIST=false
SHOW_FIREWALL=true
SHOW_FIREWALL_RULES=false
SHOW_UPDATES=true
SERVICES_STATUS_ENABLED=false

# Настройка списка для Services Status 
SERVICES=()

# Формат ввода:
# ("crowdsec" "ufw" "cron" "postfix" "ssh" "alloy" "docker" "netbird")

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
    SHOW_NET=false
    SHOW_DOCKER=true
    SHOW_DOCKER_STATUS=true
    SHOW_DOCKER_RUNNING_LIST=false
    SHOW_FIREWALL=true
    SHOW_FIREWALL_RULES=false
    SHOW_UPDATES=true
    SERVICES_STATUS_ENABLED=false
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
readonly SYSTEMCTL="/bin/systemctl"

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
    if [[ "${SHOW_LOGO}" = "true" ]]; then
        echo -e "${COLOR_TITLE}Message Of The Day by distillium (v2.3.3)${RESET}"
        echo -e "${COLOR_TITLE}-----------------------------------------${RESET}"
    fi
}

show_session_info() {
    echo -e "${COLOR_TITLE}• Session Details${RESET}"

    local real_user
    real_user=$(safe_cmd /usr/bin/logname)
    if [[ "${real_user}" = "N/A" || -z "${real_user}" ]]; then
        real_user=$(safe_cmd "${WHO}" | "${AWK}" 'NR==1{print $1}')
    fi
    printf "${COLOR_LABEL}%-22s${COLOR_YELLOW}%s${RESET}\n" "User:" "${real_user:-Unknown}"

    local last_login
    last_login=$(journalctl -u ssh.service -u sshd.service -o short-iso -n 30 \
        | grep -E "Accepted (password|publickey|keyboard-interactive)" \
        | grep -w "${real_user}" \
        | tail -n 2 \
        | head -n 1 \
        | sed -n 's/^\([0-9TZ:+-]*\).* from \([0-9.]*\) port.*/\1 \2/p' \
        | while read dt ip; do
            date_str=$(date -d "$dt" "+%d %b %H:%M")
            echo "$date_str from $ip"
          done)

    if [[ -n "$last_login" ]]; then
        printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Last login:" "$last_login"
    else
        echo -e "${COLOR_LABEL}Last login:${RESET} not available"
    fi

    local uptime_fmt
    uptime_fmt=$(safe_cmd "${UPTIME}" -p | "${SED}" 's/up //')
    printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Uptime:" "${uptime_fmt:-Unknown}"
}

show_system_info() {
    echo -e "\n${COLOR_TITLE}• System Details${RESET}"
    
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
    if [[ "${SHOW_DOCKER}" == "true" ]] && [[ -x "${DOCKER}" ]]; then
        echo -e "\n${COLOR_TITLE}• Docker${RESET}"

        if [[ "${SHOW_DOCKER_STATUS}" != "true" ]] && [[ "${SHOW_DOCKER_RUNNING_LIST}" != "true" ]]; then
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Docker:" "info disabled by configuration"
            return
        fi

        local runningnamesoutput totalnamesoutput
        runningnamesoutput=$(safe_cmd "${DOCKER}" ps --format '{{.Names}}' 2>/dev/null)
        totalnamesoutput=$(safe_cmd "${DOCKER}" ps -a --format '{{.Names}}' 2>/dev/null)
        local runningcount=0 totalcount=0

        if [[ "${runningnamesoutput}" != "N/A" ]] && [[ -n "${runningnamesoutput}" ]]; then
            runningcount=$(echo "${runningnamesoutput}" | "${WC}" -l)
        fi
        if [[ "${totalnamesoutput}" != "N/A" ]] && [[ -n "${totalnamesoutput}" ]]; then
            totalcount=$(echo "${totalnamesoutput}" | "${WC}" -l)
        fi

        if [[ "${SHOW_DOCKER_STATUS}" == "true" ]]; then
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Containers:" "${runningcount} / ${totalcount}"
        fi

        if [[ "${SHOW_DOCKER_RUNNING_LIST}" == "true" ]] && [[ "${runningcount}" -gt 0 ]] && [[ "${runningnamesoutput}" != "N/A" ]]; then
            echo -e "${COLOR_LABEL}Running Containers:${RESET}"
            local names_array=()
            while IFS= read -r line; do
                [[ -n "$line" ]] && names_array+=("$line")
            done <<< "${runningnamesoutput}"
            for ((i = 0; i < ${#names_array[@]}; i+=2)); do
                if [[ $((i + 1)) -lt ${#names_array[@]} ]]; then
                    printf " ${COLOR_VALUE}%-30s%-30s${RESET}\n" "${names_array[$i]}" "${names_array[$((i + 1))]}"
                else
                    printf " ${COLOR_VALUE}%-30s${RESET}\n" "${names_array[$i]}"
                fi
            done
        fi

    elif [[ "${SHOW_DOCKER}" == "true" ]]; then
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

show_services_info() {
  source /etc/dist-motd.conf || true

  if [[ "${SERVICES_STATUS_ENABLED,,}" != "true" ]]; then
    return
  fi

  echo -e "\n${COLOR_TITLE}• Services Status${RESET}"

  if [[ ${#SERVICES[@]} -eq 0 ]]; then
    printf "${COLOR_YELLOW}Настройте список сервисов через motd-set.${RESET}"
    return
  fi

  for service in "${SERVICES[@]}"; do
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl is-active --quiet "$service"; then
        printf "${COLOR_LABEL}%-22s${COLOR_GREEN}%s${RESET}\n" "$service:" "active"
      elif systemctl is-enabled --quiet "$service"; then
        printf "${COLOR_LABEL}%-22s${COLOR_YELLOW}%s${RESET}\n" "$service:" "inactive"
      else
        printf "${COLOR_LABEL}%-22s${COLOR_RED}%s${RESET}\n" "$service:" "disabled/not installed"
      fi
    else
      printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "$service:" "systemctl not available"
    fi
  done
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
    show_services_info
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
        CHOICE=$("${WHIPTAIL}" --title "MOTD v2.3.3" --menu \
        "Выберите действие:" 15 60 4 \
        "1" "Настроить отображение MOTD" \
        "2" "Настроить Services Status" \
        "3" "Удалить кастомный MOTD (с полным восстановлением)" \
        "4" "Показать статус установки" \
        "5" "Выход" \
        3>&1 1>&2 2>&3)
        
        case $CHOICE in
            1) configure_motd_display ;;
            2) manage_services_status_menu ;;
            3) confirm_uninstall ;;
            4) show_installation_status ;;
            5) exit 0 ;;
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
    "Выберите, что отображать в MOTD:" 20 80 12 \
    "SHOW_LOGO" "Заголовок MOTD" "$(check_setting 'SHOW_LOGO')" \
    "SHOW_CPU" "Загрузка процессора" "$(check_setting 'SHOW_CPU')" \
    "SHOW_MEM" "Память и диск" "$(check_setting 'SHOW_MEM')" \
    "SHOW_NET" "Сетевой трафик" "$(check_setting 'SHOW_NET')" \
    "SHOW_FIREWALL" "Статус UFW" "$(check_setting 'SHOW_FIREWALL')" \
    "SHOW_FIREWALL_RULES" "Правила UFW" "$(check_setting 'SHOW_FIREWALL_RULES')" \
    "SHOW_DOCKER" "Контейнеры Docker (общий выключатель)" "$(check_setting 'SHOW_DOCKER')" \
    "SHOW_DOCKER_STATUS" "Количество запущенных контейнеров" "$(check_setting 'SHOW_DOCKER_STATUS')" \
    "SHOW_DOCKER_RUNNING_LIST" "Список запущенных контейнеров" "$(check_setting 'SHOW_DOCKER_RUNNING_LIST')" \
    "SHOW_UPDATES" "Доступные обновления пакетов" "$(check_setting 'SHOW_UPDATES')" \
    3>&1 1>&2 2>&3)
    
    if [[ $? -eq 0 ]]; then
        local VARIABLES=(
            "SHOW_LOGO" "SHOW_CPU" "SHOW_MEM" "SHOW_NET"
            "SHOW_FIREWALL" "SHOW_FIREWALL_RULES"
            "SHOW_DOCKER" "SHOW_DOCKER_STATUS" "SHOW_DOCKER_RUNNING_LIST"
            "SHOW_UPDATES"
        )
        
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

manage_services_status_menu() {
  while true; do
    CHOICE=$(whiptail --title "Настройка Services Status" --menu "Выберите действие:" 12 50 4 \
      "1" "Включить/Отключить отображение" \
      "2" "Настроить список сервисов" \
      "0" "Назад" 3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ $exitstatus != 0 ]; then
      break
    fi

    case "$CHOICE" in
      "1")
        toggle_services_status
        ;;
      "2")
        edit_services_list
        ;;
      "0")
        break
        ;;
    esac
  done
}

toggle_services_status() {
  local config_file="/etc/dist-motd.conf"
  source "$config_file" || true

  if [[ "$SERVICES_STATUS_ENABLED" == "true" ]]; then
    sed -i 's/^SERVICES_STATUS_ENABLED=true/SERVICES_STATUS_ENABLED=false/' "$config_file"
  else
    if ! grep -q '^SERVICES_STATUS_ENABLED=' "$config_file"; then
      echo 'SERVICES_STATUS_ENABLED=true' >> "$config_file"
    else
      sed -i 's/^SERVICES_STATUS_ENABLED=.*/SERVICES_STATUS_ENABLED=true/' "$config_file"
    fi
  fi

  whiptail --msgbox "Опция отображения статуса сервисов обновлена! Чтобы изменения вступили в силу, переподключитесь." 8 70
}

edit_services_list() {
  local config_file="/etc/dist-motd.conf"

  if [ ! -f "$config_file" ]; then
    # Создаем файл с дефолтной пустой настройкой, если не существует
    echo 'SERVICES=()' > "$config_file"
  fi

  # Открываем конфиг для редактирования через nano
  nano "$config_file"
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
        status_info+="✓ Установлен кастомный MOTD\n"
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
    check_existing_installation
    validate_system
    
    create_complete_directory_backup
    
    install_dependencies
    create_config
    create_motd_script
    create_settings_command
    create_motd_command
    configure_pam_ssh
    configure_pam_configure_motd_display() {
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
    echo "🕑 Для смены локального времени VPS и комфортного отображения в MOTD"
    echo "  введите команду $(tput bold)$(tput setaf 2)timedatectl set-timezone Europe/Moscow$(tput sgr0)"
    echo "  Данный пример установит московский часовой пояс UTC+3"
    echo ""
}

main "$@"

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

INSTALLER_LANG="ru"

select_language() {
    echo ""
    echo "Select language / Выберите язык:"
    echo "  1) Русский (ru)"
    echo "  2) English (en)"
    echo ""
    local choice
    if [[ -t 0 ]]; then
        read -r -p "Выбор / Choice [1-2, default 1]: " choice
    else
        read -r -p "Выбор / Choice [1-2, default 1]: " choice < /dev/tty
    fi
    case "${choice}" in
        2) INSTALLER_LANG="en" ;;
        *) INSTALLER_LANG="ru" ;;
    esac
}

load_language_strings() {
    if [[ "${INSTALLER_LANG}" == "en" ]]; then
        L_REINSTALL_DETECTED="Existing custom MOTD installation detected"
        L_REINSTALL_PROMPT="Do you want to reinstall? (this will completely remove the current installation and create a new one)"
        L_REINSTALL_CONFIRM="Continue? [y/N]: "
        L_REINSTALL_CONFIRMED="User confirmed reinstall"
        L_REINSTALL_DONE="Previous installation fully removed, continuing..."
        L_INSTALL_CANCELLED="Installation cancelled by user"
        L_ROOT_REQUIRED="Script must be run as superuser"
        L_DEBIAN_ONLY="This script is intended for Debian/Ubuntu systems only"
        L_CMD_NOT_FOUND="Command not found or unavailable"
        L_BACKUP_START="Creating full directory backup..."
        L_BACKUP_DIR="Creating full backup of directory"
        L_BACKUP_SAVED="Backup saved"
        L_BACKUP_NOT_FOUND="Directory not found for backup"
        L_BACKUP_DONE="Full directory backup completed"
        L_BACKUP_FILE="File saved to backup"
        L_RESTORE_START="Restoring directories from backup..."
        L_RESTORE_NO_BACKUP="Backups not found. Cannot restore."
        L_RESTORE_DIR="Restoring directory"
        L_RESTORE_DIR_DONE="Directory restored"
        L_RESTORE_DIR_MISSING="Backup not found for directory"
        L_RESTORE_FILE="File restored"
        L_RESTORE_DONE="Full directory restore completed"
        L_CLEANUP_START="Cleaning up all custom MOTD traces..."
        L_CLEANUP_DONE="Full cleanup completed"
        L_REGEN_START="Force regenerating standard MOTD..."
        L_REGEN_DONE="Standard MOTD regeneration completed"
        L_UNINSTALL_START="Performing full removal of custom MOTD..."
        L_UNINSTALL_DONE="Full removal completed, system restored"
        L_ERROR_ROLLBACK="An error occurred during installation. Rolling back..."
        L_DEPS_START="Installing dependencies..."
        L_DEPS_UPDATE_FAIL="Failed to update package list, continuing installation"
        L_DEPS_INSTALL_FAIL="Failed to install required packages"
        L_CONFIG_START="Creating MOTD configuration..."
        L_CONFIG_FAIL="Failed to create configuration file"
        L_MOTD_SCRIPT_START="Installing MOTD script..."
        L_MOTD_SCRIPT_FAIL="Failed to create executable MOTD script"
        L_SETTINGS_CMD_START="Creating motd-set configuration menu..."
        L_SETTINGS_CMD_FAIL="Failed to create settings command"
        L_MOTD_CMD_START="Creating MOTD launch command..."
        L_MOTD_CMD_FAIL="Failed to create MOTD launch command"
        L_PAM_START="Configuring PAM and SSH for MOTD..."
        L_SSH_RESTART_FAIL="Failed to restart SSH"
        L_FINALIZE_START="Finalizing setup..."
        L_INSTALL_START="Starting custom MOTD installation with full directory backup..."
        L_INSTALL_DONE="Installation completed successfully!"
        L_BANNER_TITLE="Custom MOTD installed!"
        L_BANNER_COMMANDS="Available commands:"
        L_BANNER_MOTD="  motd         - Show MOTD"
        L_BANNER_SET="  motd-set     - Settings and management"
        L_BANNER_BACKUPS="Full directory backups"
        L_BANNER_REMOVE="To remove: motd-set -> Remove"
        L_BANNER_TZ="To change your VPS local timezone for correct time display in MOTD,"
        L_BANNER_TZ_CMD="run:"
        L_BANNER_TZ_NOTE="This example sets Moscow timezone UTC+3"
    else
        L_REINSTALL_DETECTED="Обнаружена существующая установка кастомного MOTD"
        L_REINSTALL_PROMPT="Хотите переустановить? (это полностью удалит текущую установку и создаст новую)"
        L_REINSTALL_CONFIRM="Продолжить? [y/N]: "
        L_REINSTALL_CONFIRMED="Пользователь подтвердил переустановку"
        L_REINSTALL_DONE="Предыдущая установка полностью удалена, продолжаем установку..."
        L_INSTALL_CANCELLED="Установка отменена пользователем"
        L_ROOT_REQUIRED="Скрипт должен выполняться с правами суперпользователя"
        L_DEBIAN_ONLY="Скрипт предназначен только для систем Debian/Ubuntu"
        L_CMD_NOT_FOUND="Команда не найдена или недоступна"
        L_BACKUP_START="Создание полного бэкапа директорий..."
        L_BACKUP_DIR="Создание полного бэкапа директории"
        L_BACKUP_SAVED="Бэкап сохранен"
        L_BACKUP_NOT_FOUND="Не найдена директория для бэкапа"
        L_BACKUP_DONE="Полный бэкап директорий завершен"
        L_BACKUP_FILE="Файл сохранен в бэкап"
        L_RESTORE_START="Полное восстановление директорий из бэкапа..."
        L_RESTORE_NO_BACKUP="Бэкапы не найдены. Невозможно выполнить восстановление."
        L_RESTORE_DIR="Восстановление директории"
        L_RESTORE_DIR_DONE="Директория восстановлена"
        L_RESTORE_DIR_MISSING="Бэкап директории не найден"
        L_RESTORE_FILE="Файл восстановлен"
        L_RESTORE_DONE="Полное восстановление директорий завершено"
        L_CLEANUP_START="Полная очистка всех следов кастомного MOTD..."
        L_CLEANUP_DONE="Полная очистка завершена"
        L_REGEN_START="Принудительная регенерация стандартного MOTD..."
        L_REGEN_DONE="Регенерация стандартного MOTD завершена"
        L_UNINSTALL_START="Выполняется полное удаление кастомного MOTD..."
        L_UNINSTALL_DONE="Полное удаление завершено, система восстановлена"
        L_ERROR_ROLLBACK="Произошла ошибка во время установки. Выполняется полный откат..."
        L_DEPS_START="Установка зависимостей..."
        L_DEPS_UPDATE_FAIL="Не удалось обновить список пакетов, продолжаем установку"
        L_DEPS_INSTALL_FAIL="Не удалось установить необходимые пакеты"
        L_CONFIG_START="Создание конфигурации MOTD..."
        L_CONFIG_FAIL="Не удалось создать конфигурационный файл"
        L_MOTD_SCRIPT_START="Установка скрипта MOTD..."
        L_MOTD_SCRIPT_FAIL="Не удалось создать исполняемый MOTD скрипт"
        L_SETTINGS_CMD_START="Создание меню конфигурации motd-set..."
        L_SETTINGS_CMD_FAIL="Не удалось создать команду настройки"
        L_MOTD_CMD_START="Создание команды запуска MOTD..."
        L_MOTD_CMD_FAIL="Не удалось создать команду запуска MOTD"
        L_PAM_START="Настройка PAM и SSH для MOTD..."
        L_SSH_RESTART_FAIL="Не удалось перезапустить SSH"
        L_FINALIZE_START="Завершаем настройку..."
        L_INSTALL_START="Начинается установка кастомного MOTD с полным бэкапом директорий..."
        L_INSTALL_DONE="Установка завершена успешно!"
        L_BANNER_TITLE="Кастомный MOTD установлен!"
        L_BANNER_COMMANDS="Доступные команды:"
        L_BANNER_MOTD="  motd         - Показать MOTD"
        L_BANNER_SET="  motd-set     - Настройки и управление"
        L_BANNER_BACKUPS="Полные бэкапы директорий"
        L_BANNER_REMOVE="Для удаления: motd-set -> Удалить"
        L_BANNER_TZ="Для смены локального времени VPS и комфортного отображения в MOTD,"
        L_BANNER_TZ_CMD="введите команду:"
        L_BANNER_TZ_NOTE="Данный пример установит московский часовой пояс UTC+3"
    fi
}

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
    log_info "${L_BACKUP_START}"
    
    "${MKDIR}" -p "${BACKUP_ROOT}"
    "${CHMOD}" 700 "${BACKUP_ROOT}"
    
    for dir in "${DIRECTORIES_TO_BACKUP[@]}"; do
        if [[ -d "${dir}" ]]; then
            local backup_name=$(echo "${dir}" | "${SED}" 's|/|_|g' | "${SED}" 's|^_||')
            local backup_path="${BACKUP_ROOT}/${backup_name}"
            
            log_info "${L_BACKUP_DIR}: ${dir}"
            
            if command -v rsync >/dev/null 2>&1; then
                "${RSYNC}" -a --delete "${dir}/" "${backup_path}/"
            else
                "${RM}" -rf "${backup_path}" 2>/dev/null || true
                "${CP}" -a "${dir}" "${backup_path}"
            fi
            
            log_info "${L_BACKUP_SAVED}: ${backup_path}"
        else
            log_warn "${L_BACKUP_NOT_FOUND}: ${dir}"
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
            log_info "${L_BACKUP_FILE}: ${file}"
        fi
    done
    
    "${DATE}" > "${INSTALL_MARKER}"
    
    log_info "${L_BACKUP_DONE}: ${BACKUP_ROOT}"
}

restore_complete_directories() {
    log_info "${L_RESTORE_START}"
    
    if ! check_backup_exists; then
        log_error "${L_RESTORE_NO_BACKUP}"
        return 1
    fi
    
    for dir in "${DIRECTORIES_TO_BACKUP[@]}"; do
        local backup_name=$(echo "${dir}" | "${SED}" 's|/|_|g' | "${SED}" 's|^_||')
        local backup_path="${BACKUP_ROOT}/${backup_name}"
        
        if [[ -d "${backup_path}" ]]; then
            log_info "${L_RESTORE_DIR}: ${dir}"
            
            "${RM}" -rf "${dir}" 2>/dev/null || true
            "${MKDIR}" -p "$(dirname "${dir}")"
            
            if command -v rsync >/dev/null 2>&1; then
                "${RSYNC}" -a --delete "${backup_path}/" "${dir}/"
            else
                "${CP}" -a "${backup_path}" "${dir}"
            fi
            
            log_info "${L_RESTORE_DIR_DONE}: ${dir}"
        else
            log_warn "${L_RESTORE_DIR_MISSING}: ${backup_path}"
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
            log_info "${L_RESTORE_FILE}: ${file}"
        fi
    done
    
    log_info "${L_RESTORE_DONE}"
}

complete_cleanup() {
    log_info "${L_CLEANUP_START}"
    
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
    
    log_info "${L_CLEANUP_DONE}"
}

force_regenerate_standard_motd() {
    log_info "${L_REGEN_START}"
    
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
    
    log_info "${L_REGEN_DONE}"
}

complete_uninstall() {
    log_info "${L_UNINSTALL_START}"
    
    complete_cleanup
    restore_complete_directories
    force_regenerate_standard_motd
    
    "${RM}" -rf "/opt/motd"
    
    log_info "${L_UNINSTALL_DONE}"
}

cleanup_on_error() {
    log_error "${L_ERROR_ROLLBACK}"
    
    if check_backup_exists; then
        complete_uninstall
    else
        complete_cleanup
    fi
    
    exit 1
}

trap cleanup_on_error ERR

select_language
load_language_strings

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "${L_ROOT_REQUIRED}"
        exit 1
    fi
}

check_existing_installation() {
    if check_backup_exists; then
        log_warn "${L_REINSTALL_DETECTED}"
        echo "${L_REINSTALL_PROMPT}"
        
        local response
        if [[ -t 0 ]]; then
            echo -n "${L_REINSTALL_CONFIRM}"
            read -r response
        else
            echo -n "${L_REINSTALL_CONFIRM}" > /dev/tty
            read -r response < /dev/tty
        fi
        
        case "${response,,}" in
            y|yes|да|д)
                log_info "${L_REINSTALL_CONFIRMED}"
                complete_uninstall
                log_info "${L_REINSTALL_DONE}"
                ;;
            *)
                log_info "${L_INSTALL_CANCELLED}"
                exit 0
                ;;
        esac
    fi
}

validate_system() {
    if [[ ! -f "/etc/debian_version" ]]; then
        log_error "${L_DEBIAN_ONLY}"
        exit 1
    fi
    
    local required_commands=("${APT_GET}" "${SED}" "${GREP}" "${CHMOD}" "${TAR}")
    for cmd in "${required_commands[@]}"; do
        if [[ ! -x "${cmd}" ]]; then
            log_error "${L_CMD_NOT_FOUND}: ${cmd}"
            exit 1
        fi
    done
}

install_dependencies() {
    log_info "${L_DEPS_START}"
    
    if [[ ! -f "${APT_CONF_FILE}" ]]; then
        echo 'Acquire::ForceIPv4 "true";' > "${APT_CONF_FILE}"
        "${CHMOD}" 644 "${APT_CONF_FILE}"
    fi
    
    if ! "${APT_GET}" update -qq; then
        log_warn "${L_DEPS_UPDATE_FAIL}"
    fi
    
    local packages=("procps" "lsb-release" "whiptail" "rsync")
    if ! "${APT_GET}" install -y "${packages[@]}" > /dev/null; then
        log_error "${L_DEPS_INSTALL_FAIL}"
        exit 1
    fi
}

create_config() {
    log_info "${L_CONFIG_START}"
    
    cat > "${CONFIG_FILE}" << EOF
MOTDSET_LANG=${INSTALLER_LANG}
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
SHOW_SECURITY=false
SERVICES_STATUS_ENABLED=false

# Add the required services here to display the status, for example SERVICES=(crowdsec ufw netbird)
SERVICES=()

EOF
    
    "${CHMOD}" 644 "${CONFIG_FILE}"
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_error "${L_CONFIG_FAIL}"
        exit 1
    fi
}

create_motd_script() {
    log_info "${L_MOTD_SCRIPT_START}"
    
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
    SHOW_SECURITY=false
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
    local label_extra="${3:-}"
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
    printf "${RESET}] %d%%%s" "${percent}" "${label_extra}"
}

safe_cmd() {
    local cmd_output
    if cmd_output=$("$@" 2>/dev/null); then
        printf '%s' "${cmd_output}"
    else
        printf 'N/A'
    fi
}

format_uptime() {
    local seconds
    seconds=$(cat /proc/uptime 2>/dev/null | awk '{print int($1)}')
    if [[ -z "${seconds}" ]]; then
        echo "N/A"
        return
    fi
    local days=$(( seconds / 86400 ))
    local hours=$(( (seconds % 86400) / 3600 ))
    local mins=$(( (seconds % 3600) / 60 ))
    if [[ ${days} -gt 0 ]]; then
        echo "${days} days ${hours}h ${mins}m"
    elif [[ ${hours} -gt 0 ]]; then
        echo "${hours}h ${mins}m"
    else
        echo "${mins}m"
    fi
}

show_logo() {
    if [[ "${SHOW_LOGO}" = "true" ]]; then
        echo -e "${COLOR_TITLE}Message Of The Day by distillium (v2.4.0)${RESET}"
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
    uptime_fmt=$(format_uptime)
    printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Uptime:" "${uptime_fmt}"
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
            local mem_total mem_used mem_total_mb mem_used_mb
            mem_total=$(safe_cmd "${FREE}" -m | "${AWK}" '/Mem:/ {print $2}')
            mem_used=$(safe_cmd "${FREE}" -m | "${AWK}" '/Mem:/ {print $3}')
            
            printf "${COLOR_LABEL}%-22s" "RAM:"
            if [[ "${mem_total}" =~ ^[0-9]+$ ]] && [[ "${mem_used}" =~ ^[0-9]+$ ]]; then
                local mem_label
                if [[ "${mem_total}" -ge 1024 ]]; then
                    mem_label=$(awk "BEGIN {printf \" (%d MB / %d MB)\", ${mem_used}, ${mem_total}}")
                else
                    mem_label=" (${mem_used} MB / ${mem_total} MB)"
                fi
                bar "${mem_used}" "${mem_total}" "${mem_label}"
            else
                printf "N/A"
            fi
            echo
        fi
        
        if [[ -x "${DF}" ]]; then
            local disk_used disk_total disk_used_gb disk_total_gb
            disk_used=$(safe_cmd "${DF}" -m / | "${AWK}" 'NR==2{print $3}')
            disk_total=$(safe_cmd "${DF}" -m / | "${AWK}" 'NR==2{print $2}')
            
            printf "${COLOR_LABEL}%-22s" "Disk:"
            if [[ "${disk_used}" =~ ^[0-9]+$ ]] && [[ "${disk_total}" =~ ^[0-9]+$ ]]; then
                local disk_label
                disk_label=$(awk "BEGIN {printf \" (%.1f GB / %.1f GB)\", ${disk_used}/1024, ${disk_total}/1024}")
                bar "${disk_used}" "${disk_total}" "${disk_label}"
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

show_security_info() {
    if [[ "${SHOW_SECURITY}" != "true" ]]; then
        return
    fi

    echo -e "\n${COLOR_TITLE}• Security${RESET}"

    local failed_count failed_last
    failed_count=$(journalctl -u ssh.service -u sshd.service --since "7 days ago" 2>/dev/null \
        | grep -c "Failed password\|Invalid user\|authentication failure" 2>/dev/null || echo "0")
    if [[ ! "${failed_count}" =~ ^[0-9]+$ ]]; then
        failed_count=0
    fi

    if [[ "${failed_count}" -gt 0 ]]; then
        failed_last=$(journalctl -u ssh.service -u sshd.service --since "7 days ago" -o short-iso 2>/dev/null \
            | grep "Failed password\|Invalid user\|authentication failure" \
            | tail -1 \
            | awk '{print $1}' \
            | xargs -I{} date -d "{}" "+%d %b %H:%M" 2>/dev/null || echo "")

        printf "${COLOR_LABEL}%-22s${COLOR_RED}%s${RESET}" "Failed logins (7d):" "${failed_count} attempts"
        if [[ -n "${failed_last}" ]]; then
            printf "${COLOR_VALUE} (last: %s)${RESET}" "${failed_last}"
        fi
        echo
    else
        printf "${COLOR_LABEL}%-22s${COLOR_GREEN}%s${RESET}\n" "Failed logins:" "none since boot"
    fi

    local real_user
    real_user=$(logname 2>/dev/null || echo "")
    if [[ -n "${real_user}" ]]; then
        local home_dir key_count
        home_dir=$(getent passwd "${real_user}" | cut -d: -f6 2>/dev/null || echo "")
        if [[ -f "${home_dir}/.ssh/authorized_keys" ]]; then
            key_count=$(grep -c "^ssh-\|^ecdsa-\|^sk-" "${home_dir}/.ssh/authorized_keys" 2>/dev/null || true); key_count=${key_count:-0}
            printf "${COLOR_LABEL}%-22s${COLOR_VALUE}%s${RESET}\n" "Authorized keys:" "${key_count} key(s)"
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
    show_security_info
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
        log_error "${L_MOTD_SCRIPT_FAIL}"
        exit 1
    fi
}

create_settings_command() {
    log_info "${L_SETTINGS_CMD_START}"
    
    cat > "${CMD_SETTINGS}" << SETTINGS_EOF
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

load_motdset_lang() {
    local lang="\${1:-ru}"
    if [[ "\${lang}" == "en" ]]; then
        MS_TITLE="MOTD v2.4.0"
        MS_MENU_PROMPT="Choose action:"
        MS_MENU_CONFIGURE="Configure MOTD display"
        MS_MENU_SERVICES="Configure Services Status"
        MS_MENU_UNINSTALL="Remove custom MOTD (with full restore)"
        MS_MENU_STATUS="Show installation status"
        MS_MENU_EXIT="Exit"
        MS_DISPLAY_TITLE="MOTD Display Settings"
        MS_DISPLAY_PROMPT="Select what to display in MOTD:"
        MS_DISPLAY_LOGO="MOTD header"
        MS_DISPLAY_CPU="CPU load"
        MS_DISPLAY_MEM="Memory and disk"
        MS_DISPLAY_NET="Network traffic"
        MS_DISPLAY_FW="UFW status"
        MS_DISPLAY_FW_RULES="UFW rules"
        MS_DISPLAY_DOCKER="Docker containers (master switch)"
        MS_DISPLAY_DOCKER_STATUS="Running containers count"
        MS_DISPLAY_DOCKER_LIST="Running containers list"
        MS_DISPLAY_SECURITY="Security (failed logins, SSH keys)"
        MS_DISPLAY_UPDATES="Available package updates"
        MS_SAVED="Settings updated!\n\nCheck result with command: motd"
        MS_SERVICES_TITLE="Services Status Settings"
        MS_SERVICES_PROMPT="Choose action:"
        MS_SERVICES_TOGGLE="Enable/Disable display"
        MS_SERVICES_EDIT="Edit services list"
        MS_SERVICES_BACK="Back"
        MS_SERVICES_UPDATED="Services display option updated! Reconnect to apply changes."
        MS_UNINSTALL_TITLE="Confirm removal"
        MS_UNINSTALL_WARN="WARNING!\n\nThis will completely remove the custom MOTD and restore the system from a full directory backup.\n\nAre you sure?"
        MS_UNINSTALL_STEP1="Cleaning up custom files..."
        MS_UNINSTALL_STEP2="Restoring directories..."
        MS_UNINSTALL_STEP3="Regenerating MOTD..."
        MS_UNINSTALL_STEP4="Restarting services..."
        MS_UNINSTALL_STEP5="Finishing..."
        MS_UNINSTALL_GAUGE="Performing full removal..."
        MS_UNINSTALL_TITLE_GAUGE="Removing MOTD"
        MS_UNINSTALL_SUCCESS="Custom MOTD fully removed!\n\nSystem restored from full backup."
        MS_UNINSTALL_ERROR="An error occurred during removal!"
        MS_UNINSTALL_NO_BACKUP="Backups not found!\nRemoval is not possible."
        MS_STATUS_TITLE="Installation status"
        MS_STATUS_INSTALLED="Custom MOTD installed"
        MS_STATUS_BACKUPS="Full directory backups"
        MS_STATUS_CONFIG="Configuration file"
        MS_STATUS_SCRIPT_ACTIVE="MOTD script active"
        MS_STATUS_SCRIPT_INACTIVE="MOTD script inactive"
        MS_STATUS_INSTALLED_DATE="Installed"
        MS_STATUS_NOT_INSTALLED="Custom MOTD not installed"
        MS_STATUS_NO_BACKUPS="Backups not found"
        MS_ERROR_NO_CONFIG="Configuration file not found"
        MS_ERROR_ROOT="Root privileges required.\n\nRun with sudo."
        MS_ERROR_NO_WHIPTAIL="whiptail is not installed"
        MS_LANG_TITLE="Language / Язык"
        MS_LANG_PROMPT="Select interface language:"
        MS_LANG_RU="Russian / Русский"
        MS_LANG_EN="English / Английский"
        MS_LANG_SAVED="Language changed. Restart motd-set to apply."
    else
        MS_TITLE="MOTD v2.4.0"
        MS_MENU_PROMPT="Выберите действие:"
        MS_MENU_CONFIGURE="Настроить отображение MOTD"
        MS_MENU_SERVICES="Настроить Services Status"
        MS_MENU_UNINSTALL="Удалить кастомный MOTD (с полным восстановлением)"
        MS_MENU_STATUS="Показать статус установки"
        MS_MENU_EXIT="Выход"
        MS_DISPLAY_TITLE="MOTD Display Settings"
        MS_DISPLAY_PROMPT="Выберите, что отображать в MOTD:"
        MS_DISPLAY_LOGO="Заголовок MOTD"
        MS_DISPLAY_CPU="Загрузка процессора"
        MS_DISPLAY_MEM="Память и диск"
        MS_DISPLAY_NET="Сетевой трафик"
        MS_DISPLAY_FW="Статус UFW"
        MS_DISPLAY_FW_RULES="Правила UFW"
        MS_DISPLAY_DOCKER="Контейнеры Docker (общий выключатель)"
        MS_DISPLAY_DOCKER_STATUS="Количество запущенных контейнеров"
        MS_DISPLAY_DOCKER_LIST="Список запущенных контейнеров"
        MS_DISPLAY_SECURITY="Безопасность (неудачные логины, SSH ключи)"
        MS_DISPLAY_UPDATES="Доступные обновления пакетов"
        MS_SAVED="Настройки обновлены!\n\nПроверьте результат командой: motd"
        MS_SERVICES_TITLE="Настройка Services Status"
        MS_SERVICES_PROMPT="Выберите действие:"
        MS_SERVICES_TOGGLE="Включить/Отключить отображение"
        MS_SERVICES_EDIT="Настроить список сервисов"
        MS_SERVICES_BACK="Назад"
        MS_SERVICES_UPDATED="Опция отображения статуса сервисов обновлена! Чтобы изменения вступили в силу, переподключитесь."
        MS_UNINSTALL_TITLE="Подтверждение удаления"
        MS_UNINSTALL_WARN="ВНИМАНИЕ!\n\nЭто действие полностью удалит кастомный MOTD и восстановит систему из полного бэкапа директорий.\n\nВы уверены?"
        MS_UNINSTALL_STEP1="Очистка кастомных файлов..."
        MS_UNINSTALL_STEP2="Восстановление директорий..."
        MS_UNINSTALL_STEP3="Регенерация MOTD..."
        MS_UNINSTALL_STEP4="Перезапуск служб..."
        MS_UNINSTALL_STEP5="Завершение..."
        MS_UNINSTALL_GAUGE="Выполняется полное удаление..."
        MS_UNINSTALL_TITLE_GAUGE="Удаление MOTD"
        MS_UNINSTALL_SUCCESS="Кастомный MOTD полностью удален!\n\nСистема восстановлена из полного бэкапа."
        MS_UNINSTALL_ERROR="Произошла ошибка при удалении!"
        MS_UNINSTALL_NO_BACKUP="Бэкапы не найдены!\nУдаление невозможно."
        MS_STATUS_TITLE="Статус установки"
        MS_STATUS_INSTALLED="Установлен кастомный MOTD"
        MS_STATUS_BACKUPS="Полные бэкапы директорий"
        MS_STATUS_CONFIG="Конфигурационный файл"
        MS_STATUS_SCRIPT_ACTIVE="MOTD скрипт активен"
        MS_STATUS_SCRIPT_INACTIVE="MOTD скрипт неактивен"
        MS_STATUS_INSTALLED_DATE="Установлен"
        MS_STATUS_NOT_INSTALLED="Кастомный MOTD не установлен"
        MS_STATUS_NO_BACKUPS="Бэкапы не найдены"
        MS_ERROR_NO_CONFIG="Конфигурационный файл не найден"
        MS_ERROR_ROOT="Требуются права суперпользователя.\n\nЗапустите с sudo."
        MS_ERROR_NO_WHIPTAIL="whiptail не установлен"
        MS_LANG_TITLE="Language / Язык"
        MS_LANG_PROMPT="Выберите язык интерфейса:"
        MS_LANG_RU="Russian / Русский"
        MS_LANG_EN="English / Английский"
        MS_LANG_SAVED="Язык изменён. Перезапустите motd-set для применения."
    fi
}

_MOTDSET_LANG="\$(grep '^MOTDSET_LANG=' "\${CONFIG}" 2>/dev/null | cut -d= -f2 | tr -d '\"' || echo 'ru')"
[[ -z "\${_MOTDSET_LANG}" ]] && _MOTDSET_LANG="ru"
load_motdset_lang "\${_MOTDSET_LANG}"

check_backup_exists() {
    [[ -f "\${INSTALL_MARKER}" ]] && [[ -d "\${BACKUP_ROOT}" ]]
}

restore_complete_directories() {
    echo "[+] Restoring directories from backup..."
    
    if ! check_backup_exists; then
        echo "[!] Backups not found."
        return 1
    fi
    
    for dir in "\${DIRECTORIES_TO_BACKUP[@]}"; do
        local backup_name=\$(echo "\${dir}" | /bin/sed 's|/|_|g' | /bin/sed 's|^_||')
        local backup_path="\${BACKUP_ROOT}/\${backup_name}"
        
        if [[ -d "\${backup_path}" ]]; then
            /bin/rm -rf "\${dir}" 2>/dev/null || true
            /bin/mkdir -p "\$(dirname "\${dir}")"
            
            if command -v rsync >/dev/null 2>&1; then
                /usr/bin/rsync -a --delete "\${backup_path}/" "\${dir}/"
            else
                /bin/cp -a "\${backup_path}" "\${dir}"
            fi
        fi
    done
    
    local important_files=("/etc/motd" "/etc/bash.bashrc")
    for file in "\${important_files[@]}"; do
        local backup_name=\$(echo "\${file}" | /bin/sed 's|/|_|g' | /bin/sed 's|^_||')
        local backup_file="\${BACKUP_ROOT}/\${backup_name}"
        
        if [[ -f "\${backup_file}" ]] || [[ -L "\${backup_file}" ]]; then
            /bin/rm -f "\${file}" 2>/dev/null || true
            /bin/cp -a "\${backup_file}" "\${file}"
        fi
    done
}

force_regenerate_standard_motd() {
    local cache_files=("/var/run/motd" "/var/run/motd.dynamic" "/run/motd" "/run/motd.dynamic")
    for cache_file in "\${cache_files[@]}"; do
        /bin/rm -f "\${cache_file}" 2>/dev/null || true
    done
    
    if command -v apt >/dev/null 2>&1; then
        apt list --upgradable > /dev/null 2>&1 || true
        if [[ -x "/usr/lib/update-notifier/apt-check" ]]; then
            /usr/lib/update-notifier/apt-check 2>&1 | head -1 > /var/lib/update-notifier/updates-available || true
        fi
    fi
    
    if [[ -d "/etc/update-motd.d" ]]; then
        if command -v run-parts >/dev/null 2>&1; then
            local temp_motd=\$(mktemp)
            run-parts --lsbsysinit /etc/update-motd.d/ > "\${temp_motd}" 2>/dev/null || true
            if [[ -s "\${temp_motd}" ]]; then
                /bin/cp "\${temp_motd}" "/var/run/motd.dynamic"
                /bin/chmod 644 "/var/run/motd.dynamic"
                /bin/cp "\${temp_motd}" "/run/motd.dynamic" 2>/dev/null || true
            fi
            /bin/rm -f "\${temp_motd}"
        fi
    fi
}

complete_cleanup() {
    local custom_files=(
        "/etc/dist-motd.conf"
        "/etc/update-motd.d/00-dist-motd"
        "/usr/local/bin/motd"
        "/usr/local/bin/motd-set"
        "/etc/apt/apt.conf.d/99force-ipv4"
    )
    for file in "\${custom_files[@]}"; do
        /bin/rm -f "\${file}" 2>/dev/null || true
    done
    local cache_files=("/var/run/motd" "/var/run/motd.dynamic" "/run/motd" "/run/motd.dynamic")
    for cache_file in "\${cache_files[@]}"; do
        /bin/rm -f "\${cache_file}" 2>/dev/null || true
    done
}

uninstall_custom_motd() {
    complete_cleanup
    restore_complete_directories
    force_regenerate_standard_motd
    
    if /bin/systemctl is-active ssh >/dev/null 2>&1; then
        /bin/systemctl reload ssh 2>/dev/null || true
    elif /bin/systemctl is-active sshd >/dev/null 2>&1; then
        /bin/systemctl reload sshd 2>/dev/null || true
    fi
    
    /bin/rm -rf "/opt/motd"
}

check_setting() {
    local setting="\$1"
    if /bin/grep -q "\${setting}=true" "\${CONFIG}" 2>/dev/null; then
        echo "ON"
    else
        echo "OFF"
    fi
}

change_language() {
    local current_lang="\$(grep '^MOTDSET_LANG=' "\${CONFIG}" 2>/dev/null | cut -d= -f2 | tr -d '\"' || echo 'ru')"
    [[ -z "\${current_lang}" ]] && current_lang="ru"

    local new_lang
    new_lang=\$("\${WHIPTAIL}" --title "\${MS_LANG_TITLE}" --menu "\${MS_LANG_PROMPT}" 10 50 2 \
        "ru" "\${MS_LANG_RU}" \
        "en" "\${MS_LANG_EN}" \
        3>&1 1>&2 2>&3) || return

    if /bin/grep -q '^MOTDSET_LANG=' "\${CONFIG}"; then
        /bin/sed -i "s|^MOTDSET_LANG=.*|MOTDSET_LANG=\${new_lang}|" "\${CONFIG}"
    else
        echo "MOTDSET_LANG=\${new_lang}" >> "\${CONFIG}"
    fi

    load_motdset_lang "\${new_lang}"
    "\${WHIPTAIL}" --title "\${MS_LANG_TITLE}" --msgbox "\${MS_LANG_SAVED}" 8 50
}

show_main_menu() {
    while true; do
        CHOICE=\$("\${WHIPTAIL}" --title "\${MS_TITLE}" --menu \
        "\${MS_MENU_PROMPT}" 16 60 5 \
        "1" "\${MS_MENU_CONFIGURE}" \
        "2" "\${MS_MENU_SERVICES}" \
        "3" "\${MS_MENU_UNINSTALL}" \
        "4" "\${MS_MENU_STATUS}" \
        "5" "Language / Язык" \
        "6" "\${MS_MENU_EXIT}" \
        3>&1 1>&2 2>&3)
        
        case \$CHOICE in
            1) configure_motd_display ;;
            2) manage_services_status_menu ;;
            3) confirm_uninstall ;;
            4) show_installation_status ;;
            5) change_language ;;
            6) exit 0 ;;
            *) exit 0 ;;
        esac
    done
}

configure_motd_display() {
    if [[ ! -f "\${CONFIG}" ]]; then
        "\${WHIPTAIL}" --title "Error" --msgbox "\${MS_ERROR_NO_CONFIG}: \${CONFIG}" 8 60
        return
    fi
    
    CHOICES=\$("\${WHIPTAIL}" --title "\${MS_DISPLAY_TITLE}" --checklist \
    "\${MS_DISPLAY_PROMPT}" 22 80 11 \
    "SHOW_LOGO"               "\${MS_DISPLAY_LOGO}"          "\$(check_setting 'SHOW_LOGO')" \
    "SHOW_CPU"                "\${MS_DISPLAY_CPU}"           "\$(check_setting 'SHOW_CPU')" \
    "SHOW_MEM"                "\${MS_DISPLAY_MEM}"           "\$(check_setting 'SHOW_MEM')" \
    "SHOW_NET"                "\${MS_DISPLAY_NET}"           "\$(check_setting 'SHOW_NET')" \
    "SHOW_FIREWALL"           "\${MS_DISPLAY_FW}"            "\$(check_setting 'SHOW_FIREWALL')" \
    "SHOW_FIREWALL_RULES"     "\${MS_DISPLAY_FW_RULES}"      "\$(check_setting 'SHOW_FIREWALL_RULES')" \
    "SHOW_DOCKER"             "\${MS_DISPLAY_DOCKER}"        "\$(check_setting 'SHOW_DOCKER')" \
    "SHOW_DOCKER_STATUS"      "\${MS_DISPLAY_DOCKER_STATUS}" "\$(check_setting 'SHOW_DOCKER_STATUS')" \
    "SHOW_DOCKER_RUNNING_LIST" "\${MS_DISPLAY_DOCKER_LIST}"  "\$(check_setting 'SHOW_DOCKER_RUNNING_LIST')" \
    "SHOW_SECURITY"           "\${MS_DISPLAY_SECURITY}"      "\$(check_setting 'SHOW_SECURITY')" \
    "SHOW_UPDATES"            "\${MS_DISPLAY_UPDATES}"       "\$(check_setting 'SHOW_UPDATES')" \
    3>&1 1>&2 2>&3)
    
    if [[ \$? -eq 0 ]]; then
        local VARIABLES=(
            "SHOW_LOGO" "SHOW_CPU" "SHOW_MEM" "SHOW_NET"
            "SHOW_FIREWALL" "SHOW_FIREWALL_RULES"
            "SHOW_DOCKER" "SHOW_DOCKER_STATUS" "SHOW_DOCKER_RUNNING_LIST"
            "SHOW_SECURITY" "SHOW_UPDATES"
        )
        
        for var in "\${VARIABLES[@]}"; do
            if echo "\${CHOICES}" | /bin/grep -q "\${var}"; then
                /bin/sed -i "s/^\${var}=.*/\${var}=true/" "\${CONFIG}"
            else
                /bin/sed -i "s/^\${var}=.*/\${var}=false/" "\${CONFIG}"
            fi
        done

        if ! /bin/grep -q "^SHOW_SECURITY=" "\${CONFIG}"; then
            if echo "\${CHOICES}" | /bin/grep -q "SHOW_SECURITY"; then
                echo "SHOW_SECURITY=true" >> "\${CONFIG}"
            else
                echo "SHOW_SECURITY=false" >> "\${CONFIG}"
            fi
        fi
        
        "\${WHIPTAIL}" --title "OK" --msgbox "\${MS_SAVED}" 10 50
    fi
}

manage_services_status_menu() {
  while true; do
    CHOICE=\$(whiptail --title "\${MS_SERVICES_TITLE}" --menu "\${MS_SERVICES_PROMPT}" 12 55 3 \
      "1" "\${MS_SERVICES_TOGGLE}" \
      "2" "\${MS_SERVICES_EDIT}" \
      "0" "\${MS_SERVICES_BACK}" 3>&1 1>&2 2>&3)

    exitstatus=\$?
    if [ \$exitstatus != 0 ]; then
      break
    fi

    case "\$CHOICE" in
      "1") toggle_services_status ;;
      "2") edit_services_list ;;
      "0") break ;;
    esac
  done
}

toggle_services_status() {
  source "\$CONFIG" || true

  if [[ "\$SERVICES_STATUS_ENABLED" == "true" ]]; then
    sed -i 's/^SERVICES_STATUS_ENABLED=true/SERVICES_STATUS_ENABLED=false/' "\$CONFIG"
  else
    if ! grep -q '^SERVICES_STATUS_ENABLED=' "\$CONFIG"; then
      echo 'SERVICES_STATUS_ENABLED=true' >> "\$CONFIG"
    else
      sed -i 's/^SERVICES_STATUS_ENABLED=.*/SERVICES_STATUS_ENABLED=true/' "\$CONFIG"
    fi
  fi

  whiptail --msgbox "\${MS_SERVICES_UPDATED}" 8 70
}

edit_services_list() {
  local config_file="/etc/dist-motd.conf"

  if [ ! -f "\$config_file" ]; then
    echo 'SERVICES=()' > "\$config_file"
  fi

  nano "\$config_file"
}

confirm_uninstall() {
    if ! check_backup_exists; then
        "\${WHIPTAIL}" --title "Error" --msgbox "\${MS_UNINSTALL_NO_BACKUP}" 10 60
        return
    fi
    
    if "\${WHIPTAIL}" --title "\${MS_UNINSTALL_TITLE}" --yesno "\${MS_UNINSTALL_WARN}" 12 70; then
        
        (
            echo "10"; echo "\${MS_UNINSTALL_STEP1}"
            sleep 1
            echo "40"; echo "\${MS_UNINSTALL_STEP2}"
            sleep 1
            echo "70"; echo "\${MS_UNINSTALL_STEP3}"
            sleep 1
            echo "90"; echo "\${MS_UNINSTALL_STEP4}"
            sleep 1
            echo "100"; echo "\${MS_UNINSTALL_STEP5}"
            sleep 1
        ) | "\${WHIPTAIL}" --title "\${MS_UNINSTALL_TITLE_GAUGE}" --gauge "\${MS_UNINSTALL_GAUGE}" 8 60 0
        
        if uninstall_custom_motd >/dev/null 2>&1; then
            "\${WHIPTAIL}" --title "OK" --msgbox "\${MS_UNINSTALL_SUCCESS}" 10 50
            exit 0
        else
            "\${WHIPTAIL}" --title "Error" --msgbox "\${MS_UNINSTALL_ERROR}" 8 50
        fi
    fi
}

show_installation_status() {
    local status_info=""
    
    if check_backup_exists; then
        status_info+="✓ \${MS_STATUS_INSTALLED}\n"
        status_info+="✓ \${MS_STATUS_BACKUPS}: \${BACKUP_ROOT}\n"
        
        if [[ -f "\${CONFIG}" ]]; then
            status_info+="✓ \${MS_STATUS_CONFIG}: \${CONFIG}\n"
        else
            status_info+="✗ \${MS_STATUS_CONFIG} not found\n"
        fi
        
        if [[ -x "/etc/update-motd.d/00-dist-motd" ]]; then
            status_info+="✓ \${MS_STATUS_SCRIPT_ACTIVE}\n"
        else
            status_info+="✗ \${MS_STATUS_SCRIPT_INACTIVE}\n"
        fi
        
        if [[ -f "\${INSTALL_MARKER}" ]]; then
            local install_date
            install_date=\$(cat "\${INSTALL_MARKER}")
            status_info+="📅 \${MS_STATUS_INSTALLED_DATE}: \${install_date}\n"
        fi
        
    else
        status_info+="✗ \${MS_STATUS_NOT_INSTALLED}\n"
        status_info+="✗ \${MS_STATUS_NO_BACKUPS}\n"
    fi
    
    "\${WHIPTAIL}" --title "\${MS_STATUS_TITLE}" --msgbox "\${status_info}" 15 70
}

if [[ "\${EUID}" -ne 0 ]]; then
    "\${WHIPTAIL}" --title "Error" --msgbox "\${MS_ERROR_ROOT}" 8 50
    exit 1
fi

if [[ ! -x "\${WHIPTAIL}" ]]; then
    echo "\${MS_ERROR_NO_WHIPTAIL}" >&2
    exit 1
fi

show_main_menu
SETTINGS_EOF

    "${CHMOD}" 755 "${CMD_SETTINGS}"
    
    if [[ ! -x "${CMD_SETTINGS}" ]]; then
        log_error "${L_SETTINGS_CMD_FAIL}"
        exit 1
    fi
}

create_motd_command() {
    log_info "${L_MOTD_CMD_START}"
    
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
        log_error "${L_MOTD_CMD_FAIL}"
        exit 1
    fi
}

configure_pam_ssh() {
    log_info "${L_PAM_START}"
    
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
        log_warn "${L_SSH_RESTART_FAIL}"
    fi
}

finalize_setup() {
    log_info "${L_FINALIZE_START}"
    
    "${SED}" -i 's|^#\s*\(session\s\+optional\s\+pam_motd\.so\s\+motd=/run/motd\.dynamic\)|\1|' /etc/pam.d/sshd 2>/dev/null || true
    "${SED}" -i 's|^#\s*\(session\s\+optional\s\+pam_motd\.so\s\+noupdate\)|\1|' /etc/pam.d/sshd 2>/dev/null || true
    
    "${CHMOD}" -x /etc/update-motd.d/* 2>/dev/null || true
    "${CHMOD}" +x "${MOTD_SCRIPT}"
    
    "${RM}" -f /etc/motd 2>/dev/null || true
    "${LN}" -sf /var/run/motd /etc/motd 2>/dev/null || true
}

main() {
    log_info "${L_INSTALL_START}"
    
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
    restart_ssh_service
    finalize_setup
    
    log_info "${L_INSTALL_DONE}"
    echo ""
    echo "========================================================="
    echo "             🎉 ${L_BANNER_TITLE}"
    echo "========================================================="
    echo ""
    echo "📋 ${L_BANNER_COMMANDS}"
    echo "${L_BANNER_MOTD}"
    echo "${L_BANNER_SET}"
    echo ""
    echo "💾 ${L_BANNER_BACKUPS}: ${BACKUP_ROOT}"
    echo "🔄 ${L_BANNER_REMOVE}"
    echo ""
    echo "🕑 ${L_BANNER_TZ}"
    echo "  ${L_BANNER_TZ_CMD} $(tput bold)$(tput setaf 2)timedatectl set-timezone Europe/Moscow$(tput sgr0)"
    echo "  ${L_BANNER_TZ_NOTE}"
    echo ""
}

main "$@"

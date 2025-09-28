#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для вывода сообщений
print_message() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Функция для проверки прав root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен быть запущен с правами root"
        exit 1
    fi
}

# Функция установки необходимых утилит
install_utilities() {
    print_message "Проверка и установка необходимых утилит..."
    
    # Обновляем список пакетов
    apt update
    
    # Проверяем и устанавливаем netstat если нужно
    if ! command -v netstat &> /dev/null && ! command -v ss &> /dev/null; then
        print_message "Установка net-tools..."
        apt install net-tools -y
    fi
    
    # Проверяем curl
    if ! command -v curl &> /dev/null; then
        print_message "Установка curl..."
        apt install curl -y
    fi
    
    # Проверяем wget
    if ! command -v wget &> /dev/null; then
        print_message "Установка wget..."
        apt install wget -y
    fi
    
    # Проверяем ufw
    if ! command -v ufw &> /dev/null; then
        print_message "Установка ufw..."
        apt install ufw -y
    fi
}

# Функция для паузы
pause() {
    read -p "Нажмите Enter для продолжения..."
}

# Главное меню
main_menu() {
    clear
    echo "=========================================="
    echo "  Настройка VPS Ubuntu 24.04"
    echo "=========================================="
    echo "1. Обновление системы"
    echo "2. Настройка SSH"
    echo "3. Настройка фаервола"
    echo "4. Управление пингами"
    echo "5. Управление 3x-ui"
    echo "6. Управление IPv6"
    echo "0. Выход"
    echo "=========================================="
    read -p "Выберите пункт меню [0-6]: " choice
    
    case $choice in
        1) update_system ;;
        2) ssh_menu ;;
        3) firewall_menu ;;
        4) ping_menu ;;
        5) xui_menu ;;
        6) ipv6_menu ;;
        0) exit 0 ;;
        *) print_error "Неверный выбор"; pause; main_menu ;;
    esac
}

# 1. Обновление системы
update_system() {
    clear
    echo "=========================================="
    echo "  Обновление системы"
    echo "=========================================="
    
    print_message "Обновление списка пакетов..."
    apt update
    
    print_message "Обновление установленных пакетов..."
    apt upgrade -y
    
    print_message "Очистка кэша..."
    apt autoremove -y
    apt autoclean
    
    print_success "Система успешно обновлена"
    pause
    main_menu
}

# 2. Меню SSH
ssh_menu() {
    clear
    echo "=========================================="
    echo "  Настройка SSH"
    echo "=========================================="
    echo "1. Проверка и создание SSH ключей"
    echo "2. Запретить вход по паролю"
    echo "3. Разрешить вход по паролю"
    echo "4. Изменить порт SSH"
    echo "5. Назад"
    echo "=========================================="
    read -p "Выберите пункт меню [1-5]: " choice
    
    case $choice in
        1) check_and_create_ssh_keys ;;
        2) disable_password_login ;;
        3) enable_password_login ;;
        4) change_ssh_port ;;
        5) main_menu ;;
        *) print_error "Неверный выбор"; pause; ssh_menu ;;
    esac
}

check_and_create_ssh_keys() {
    clear
    echo "=========================================="
    echo "  Проверка и создание SSH ключей"
    echo "=========================================="
    
    # Создаем директорию .ssh если её нет
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    # Проверяем существование ключей Ed25519
    if [ -f ~/.ssh/id_ed25519 ] && [ -f ~/.ssh/id_ed25519.pub ]; then
        print_warning "SSH ключи Ed25519 уже существуют:"
        echo -e "\n${GREEN}=== Публичный ключ ===${NC}"
        cat ~/.ssh/id_ed25519.pub
        echo -e "\n${GREEN}=== Приватный ключ ===${NC}"
        cat ~/.ssh/id_ed25519
        echo -e "\n${GREEN}=== Отпечаток ключа ===${NC}"
        ssh-keygen -lf ~/.ssh/id_ed25519.pub
        
        echo -e "\n${YELLOW}Публичный ключ для копирования:${NC}"
        echo "----------------------------------------"
        cat ~/.ssh/id_ed25519.pub
        echo "----------------------------------------"
        
        read -p "Создать новые ключи? (y/N): " create_new
        if [[ ! $create_new =~ ^[Yy]$ ]]; then
            print_message "Создание ключей отменено"
            pause
            ssh_menu
            return
        fi
        
        # Создаем backup существующих ключей
        backup_dir="/root/ssh_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp ~/.ssh/id_ed25519* "$backup_dir/" 2>/dev/null
        cp ~/.ssh/id_rsa* "$backup_dir/" 2>/dev/null
        print_message "Старые ключи сохранены в: $backup_dir"
        
        rm -f ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub
    fi
    
    read -p "Введите email для SSH ключа: " email
    read -p "Введите парольную фразу для ключа (можно оставить пустым): " passphrase
    
    print_message "Создание SSH ключа Ed25519 (рекомендуемый алгоритм)..."
    if [ -z "$passphrase" ]; then
        ssh-keygen -t ed25519 -C "$email" -f ~/.ssh/id_ed25519 -N ""
    else
        ssh-keygen -t ed25519 -C "$email" -f ~/.ssh/id_ed25519 -N "$passphrase"
    fi
    
    print_success "SSH ключи Ed25519 созданы"
    
    echo -e "\n${GREEN}=== Публичный ключ ===${NC}"
    cat ~/.ssh/id_ed25519.pub
    echo -e "\n${GREEN}=== Приватный ключ ===${NC}"
    cat ~/.ssh/id_ed25519
    echo -e "\n${GREEN}=== Отпечаток ключа ===${NC}"
    ssh-keygen -lf ~/.ssh/id_ed25519.pub
    
    echo -e "\n${YELLOW}=== Публичный ключ для копирования ===${NC}"
    echo "----------------------------------------"
    cat ~/.ssh/id_ed25519.pub
    echo "----------------------------------------"
    
    # Копирование ключа для авторизации
    cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    
    echo -e "\n${YELLOW}Сохраните приватный ключ в безопасном месте!${NC}"
    echo -e "${YELLOW}Публичный ключ добавлен в authorized_keys${NC}"
    pause
    ssh_menu
}

disable_password_login() {
    clear
    echo "=========================================="
    echo "  Запрет входа по паролю"
    echo "=========================================="
    
    if [ ! -f ~/.ssh/authorized_keys ] || [ ! -s ~/.ssh/authorized_keys ]; then
        print_error "Нет настроенных SSH ключей. Сначала создайте ключи."
        pause
        ssh_menu
        return
    fi
    
    print_warning "ВНИМАНИЕ: Убедитесь, что у вас есть доступ по SSH ключу!"
    print_warning "После этой операции войти по паролю будет невозможно!"
    read -p "Продолжить? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Создаем backup конфига
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
        
        # Отключаем аутентификацию по паролю
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
        
        # Включаем аутентификацию по ключам
        sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        
        # Убеждаемся что разрешена аутентификация по ключам
        if ! grep -q "PubkeyAuthentication yes" /etc/ssh/sshd_config; then
            echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
        fi
        
        # Добавляем настройку запрета пароля, если её нет
        if ! grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
            echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
        fi
        
        # Дополнительные настройки безопасности
        sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        
        systemctl restart ssh
        print_success "Настройки SSH применены:"
        print_success "✓ Вход по паролю ЗАПРЕЩЕН"
        print_success "✓ Вход по ключу РАЗРЕШЕН"
        print_success "✓ Root вход только по ключу"
        print_message "Резервная копия конфига создана: /etc/ssh/sshd_config.backup"
    else
        print_message "Операция отменена"
    fi
    
    pause
    ssh_menu
}

enable_password_login() {
    clear
    echo "=========================================="
    echo "  Разрешение входа по паролю"
    echo "=========================================="
    
    print_warning "ВНИМАНИЕ: Разрешение входа по паролю снижает безопасность!"
    read -p "Продолжить? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Создаем backup конфига
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
        
        # Включаем аутентификацию по паролю
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
        
        # Убеждаемся что разрешена аутентификация по паролю
        if ! grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config; then
            echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
        fi
        
        # Также разрешаем аутентификацию по ключам (для гибкости)
        sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        
        systemctl restart ssh
        print_success "Настройки SSH применены:"
        print_success "✓ Вход по паролю РАЗРЕШЕН"
        print_success "✓ Вход по ключу РАЗРЕШЕН"
        print_warning "✓ Root вход по паролю разрешен (небезопасно!)"
        print_message "Резервная копия конфига создана: /etc/ssh/sshd_config.backup"
        print_warning "Рекомендуется использовать сложные пароли!"
    else
        print_message "Операция отменена"
    fi
    
    pause
    ssh_menu
}

change_ssh_port() {
    clear
    echo "=========================================="
    echo "  Изменение порта SSH"
    echo "=========================================="
    
    current_port=$(grep -E "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    if [ -n "$current_port" ]; then
        print_message "Текущий порт SSH: $current_port"
    else
        print_message "Текущий порт SSH: 22 (по умолчанию)"
        current_port=22
    fi
    
    read -p "Введите новый порт SSH (1024-65535): " new_port
    
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1024 ] || [ "$new_port" -gt 65535 ]; then
        print_error "Неверный порт. Должен быть в диапазоне 1024-65535"
        pause
        ssh_menu
        return
    fi
    
    # Проверяем, не используется ли порт другим сервисом
    if ss -tulpn | grep ":$new_port " > /dev/null; then
        print_error "Порт $new_port уже используется другим сервисом!"
        pause
        ssh_menu
        return
    fi
    
    # Резервное копирование конфига
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
    
    # Изменение порта в конфиге
    if grep -q "^Port" /etc/ssh/sshd_config; then
        sed -i "s/^Port.*/Port $new_port/" /etc/ssh/sshd_config
    else
        # Если директивы Port нет, добавляем её в начало файла
        sed -i "1iPort $new_port" /etc/ssh/sshd_config
    fi
    
    # Убедимся, что есть ListenAddress
    if ! grep -q "^ListenAddress" /etc/ssh/sshd_config; then
        echo "ListenAddress 0.0.0.0" >> /etc/ssh/sshd_config
        echo "ListenAddress ::" >> /etc/ssh/sshd_config
    fi
    
    # Проверяем синтаксис конфига перед перезапуском
    if ! sshd -t; then
        print_error "Ошибка в конфигурации SSH! Восстанавливаем backup..."
        cp /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) /etc/ssh/sshd_config
        systemctl restart ssh
        print_error "Порт SSH не изменен из-за ошибки конфигурации"
        pause
        ssh_menu
        return
    fi
    
    # Перезапускаем SSH
    systemctl restart ssh
    
    # Ждем немного чтобы сервер запустился
    sleep 2
    
    # Проверяем, слушает ли SSH новый порт
    if ss -tulpn | grep ":$new_port " > /dev/null; then
        print_success "SSH успешно запущен на порту $new_port"
    else
        print_error "SSH не слушает новый порт $new_port! Восстанавливаем старую конфигурацию..."
        cp /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) /etc/ssh/sshd_config
        systemctl restart ssh
        print_error "Порт SSH не изменен"
        pause
        ssh_menu
        return
    fi
    
    # Управление портами в фаерволе
    if command -v ufw &> /dev/null; then
        print_message "Настройка фаервола..."
        
        # Включаем фаервол если выключен
        if ufw status | grep -q "inactive"; then
            ufw --force enable
        fi
        
        # Открываем новый порт
        ufw allow $new_port/tcp
        print_success "Новый порт $new_port открыт в фаерволе"
        
        # Закрываем старый порт (всегда, независимо от того открыт ли он)
        if [ "$current_port" != "$new_port" ]; then
            # Пытаемся закрыть старый порт, игнорируем ошибки если порт не открыт
            ufw delete allow $current_port/tcp 2>/dev/null || true
            print_success "Старый порт $current_port закрыт в фаерволе"
            
            # Также закрываем порт 22 если он отличается от нового
            if [ "$current_port" = "22" ] && [ "$new_port" != "22" ]; then
                ufw delete allow 22/tcp 2>/dev/null || true
                print_success "Стандартный порт 22 закрыт в фаерволе"
            fi
        fi
    else
        print_warning "UFW не установлен. Не забудьте настроить фаервол вручную!"
    fi
    
    # Показываем итоговую информацию
    echo -e "\n${GREEN}=== Итоговые настройки ===${NC}"
    echo "Старый порт SSH: $current_port"
    echo "Новый порт SSH: $new_port"
    echo -e "\n${YELLOW}Команда для подключения:${NC}"
    echo "ssh -p $new_port $(whoami)@$(curl -s ifconfig.me || hostname -I | awk '{print $1}')"
    
    print_success "Порт SSH успешно изменен на $new_port"
    print_message "Резервная копия конфига создана: /etc/ssh/sshd_config.backup"
    print_warning "Проверьте подключение по новому порту перед закрытием старой сессии!"
    
    pause
    ssh_menu
}

# 3. Меню фаервола
firewall_menu() {
    clear
    echo "=========================================="
    echo "  Настройка фаервола"
    echo "=========================================="
    echo "1. Включить фаервол"
    echo "2. Отключить фаервол"
    echo "3. Настройка портов"
    echo "4. Статистика фаервола"
    echo "5. Назад"
    echo "=========================================="
    read -p "Выберите пункт меню [1-5]: " choice
    
    case $choice in
        1) enable_firewall ;;
        2) disable_firewall ;;
        3) configure_ports ;;
        4) firewall_stats ;;
        5) main_menu ;;
        *) print_error "Неверный выбор"; pause; firewall_menu ;;
    esac
}

enable_firewall() {
    clear
    echo "=========================================="
    echo "  Включение фаервола"
    echo "=========================================="
    
    # Установка ufw если не установлен
    if ! command -v ufw &> /dev/null; then
        print_message "Установка UFW..."
        apt update
        apt install ufw -y
    fi
    
    # Базовая настройка по умолчанию
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw --force enable
    print_success "Фаервол включен"
    print_message "По умолчанию: входящие соединения запрещены, исходящие разрешены"
    pause
    firewall_menu
}

disable_firewall() {
    clear
    echo "=========================================="
    echo "  Отключение фаервола"
    echo "=========================================="
    
    read -p "Вы уверены, что хотите отключить фаервол? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        ufw disable
        print_success "Фаервол отключен"
    else
        print_message "Операция отменена"
    fi
    
    pause
    firewall_menu
}

configure_ports() {
    clear
    echo "=========================================="
    echo "  Настройка портов"
    echo "=========================================="
    
    # Получаем текущий порт SSH
    current_ssh_port=$(grep -E "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    if [ -z "$current_ssh_port" ]; then
        current_ssh_port="22"
    fi
    
    echo "1. Разрешить порт"
    echo "2. Запретить порт"
    echo "3. Разрешить SSH (порт $current_ssh_port)"
    echo "4. Показать текущие правила"
    echo "5. Назад"
    echo "=========================================="
    read -p "Выберите пункт меню [1-5]: " choice
    
    case $choice in
        1) allow_port ;;
        2) deny_port ;;
        3) allow_ssh ;;
        4) show_rules ;;
        5) firewall_menu ;;
        *) print_error "Неверный выбор"; pause; configure_ports ;;
    esac
}

allow_port() {
    read -p "Введите порт для разрешения: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        print_error "Неверный порт. Должен быть в диапазоне 1-65535"
        pause
        configure_ports
        return
    fi
    
    read -p "Введите протокол (tcp/udp, по умолчанию tcp): " protocol
    protocol=${protocol:-tcp}
    
    if ufw allow $port/$protocol; then
        print_success "Порт $port/$protocol разрешен"
    else
        print_error "Ошибка при открытии порта"
    fi
    
    pause
    configure_ports
}

deny_port() {
    read -p "Введите порт для запрета: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        print_error "Неверный порт. Должен быть в диапазоне 1-65535"
        pause
        configure_ports
        return
    fi
    
    read -p "Введите протокол (tcp/udp, по умолчанию tcp): " protocol
    protocol=${protocol:-tcp}
    
    if ufw deny $port/$protocol; then
        print_success "Порт $port/$protocol запрещен"
    else
        print_error "Ошибка при запрете порта"
    fi
    
    pause
    configure_ports
}

allow_ssh() {
    # Получаем текущий порт SSH
    current_ssh_port=$(grep -E "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    if [ -z "$current_ssh_port" ]; then
        current_ssh_port="22"
    fi
    
    ufw allow $current_ssh_port/tcp
    print_success "SSH порт ($current_ssh_port) разрешен"
    pause
    configure_ports
}

show_rules() {
    clear
    echo "=========================================="
    echo "  Текущие правила UFW"
    echo "=========================================="
    ufw status numbered
    pause
    configure_ports
}

firewall_stats() {
    clear
    echo "=========================================="
    echo "  Статистика фаервола"
    echo "=========================================="
    
    if command -v ufw &> /dev/null; then
        echo "Статус UFW:"
        ufw status verbose
    else
        print_error "UFW не установлен"
    fi
    
    echo -e "\nОткрытые порты:"
    
    # Проверяем, какая команда доступна
    if command -v ss &> /dev/null; then
        ss -tulpn | grep LISTEN
    elif command -v netstat &> /dev/null; then
        netstat -tulpn | grep LISTEN
    else
        print_error "Ни ss, ни netstat не найдены. Установите один из пакетов."
        print_message "Можно установить: apt install net-tools или apt install iproute2"
    fi
    
    pause
    firewall_menu
}

# 4. Управление пингами
ping_menu() {
    clear
    echo "=========================================="
    echo "  Управление пингами"
    echo "=========================================="
    echo "1. Запретить пинги"
    echo "2. Разрешить пинги"
    echo "3. Назад"
    echo "=========================================="
    read -p "Выберите пункт меню [1-3]: " choice
    
    case $choice in
        1) disable_ping ;;
        2) enable_ping ;;
        3) main_menu ;;
        *) print_error "Неверный выбор"; pause; ping_menu ;;
    esac
}

disable_ping() {
    # Создаем backup
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # Добавляем или изменяем параметр
    if grep -q "net.ipv4.icmp_echo_ignore_all" /etc/sysctl.conf; then
        sed -i 's/net.ipv4.icmp_echo_ignore_all.*/net.ipv4.icmp_echo_ignore_all = 1/' /etc/sysctl.conf
    else
        echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
    fi
    
    sysctl -p
    print_success "Пинги запрещены"
    print_message "Резервная копия создана: /etc/sysctl.conf.backup"
    pause
    ping_menu
}

enable_ping() {
    # Создаем backup
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # Удаляем параметр
    sed -i '/net.ipv4.icmp_echo_ignore_all/d' /etc/sysctl.conf
    sysctl -p
    print_success "Пинги разрешены"
    print_message "Резервная копия создана: /etc/sysctl.conf.backup"
    pause
    ping_menu
}

# 5. 3x-ui
xui_menu() {
    clear
    echo "=========================================="
    echo "  Управление 3x-ui"
    echo "=========================================="
    echo "1. Установка 3x-ui"
    echo "2. Удаление 3x-ui"
    echo "3. Назад"
    echo "=========================================="
    read -p "Выберите пункт меню [1-3]: " choice
    
    case $choice in
        1) install_xui ;;
        2) remove_xui ;;
        3) main_menu ;;
        *) print_error "Неверный выбор"; pause; xui_menu ;;
    esac
}

install_xui() {
    clear
    print_message "Установка 3x-ui..."
    
    # Установка 3x-ui с фиксированной версией
    VERSION=v2.6.7
    print_message "Установка версии $VERSION..."
    bash <(curl -Ls "https://raw.githubusercontent.com/mhsanaei/3x-ui/$VERSION/install.sh") $VERSION
    
    # Получаем порт из конфигурации 3x-ui
    if [ -f /etc/x-ui/x-ui.db ]; then
        xui_port=$(strings /etc/x-ui/x-ui.db | grep -oP '"port":\s*\K[0-9]+' | head -1)
        if [ -n "$xui_port" ]; then
            print_message "3x-ui использует порт: $xui_port"
            
            # Сохраняем информацию о порте для последующего удаления
            echo "X_UI_PORT=$xui_port" > /tmp/x-ui-port.info
            
            # Открытие порта в фаерволе
            if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
                ufw allow $xui_port/tcp
                print_success "Порт $xui_port открыт в фаерволе"
            fi
        fi
    fi
    
    print_success "3x-ui установлен"
    pause
    xui_menu
}

remove_xui() {
    clear
    print_warning "Удаление 3x-ui..."
    
    read -p "Вы уверены, что хотите удалить 3x-ui? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Получаем порт из конфигурации 3x-ui перед удалением
        local xui_port=""
        if [ -f /etc/x-ui/x-ui.db ]; then
            xui_port=$(strings /etc/x-ui/x-ui.db | grep -oP '"port":\s*\K[0-9]+' | head -1)
        fi
        
        # Также проверяем сохраненную информацию о порте
        if [ -f /tmp/x-ui-port.info ]; then
            source /tmp/x-ui-port.info
            if [ -n "$X_UI_PORT" ]; then
                xui_port="$X_UI_PORT"
            fi
            rm -f /tmp/x-ui-port.info
        fi
        
        # Остановка службы
        systemctl stop x-ui
        systemctl disable x-ui
        
        # Удаление файлов и служб
        rm -rf /etc/x-ui
        rm -rf /usr/local/x-ui
        rm -f /etc/systemd/system/x-ui.service
        rm -f /usr/bin/x-ui
        
        systemctl daemon-reload
        
        # Закрытие портов в фаерволе
        if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
            if [ -n "$xui_port" ]; then
                # Закрываем основной порт панели
                ufw delete allow $xui_port/tcp 2>/dev/null && print_success "Порт $xui_port закрыт в фаерволе" || print_warning "Порт $xui_port не был открыт в фаерволе"
            fi
            
            # Закрываем стандартные порты, которые могут использоваться 3x-ui
            local common_ports=("54321" "2053" "2083" "2087" "2096" "8443" "8880")
            for port in "${common_ports[@]}"; do
                ufw delete allow $port/tcp 2>/dev/null && print_success "Порт $port закрыт в фаерволе" || true
            done
            
            # Также ищем и закрываем любые другие порты, связанные с x-ui
            ufw status numbered | grep -E "x-ui|X-UI" | while read line; do
                local port_num=$(echo "$line" | grep -oP '\d+/tcp' | cut -d'/' -f1)
                if [ -n "$port_num" ]; then
                    ufw delete allow $port_num/tcp 2>/dev/null && print_success "Порт $port_num (x-ui) закрыт в фаерволе"
                fi
            done
        else
            print_warning "UFW не активен, проверьте iptables/другие фаерволы вручную"
        fi
        
        print_success "3x-ui удален и все связанные порты закрыты"
    else
        print_message "Удаление отменено"
    fi
    
    pause
    xui_menu
}

# 6. Меню IPv6
ipv6_menu() {
    clear
    echo "=========================================="
    echo "  Управление IPv6"
    echo "=========================================="
    echo "1. Отключить IPv6"
    echo "2. Включить IPv6"
    echo "3. Статус IPv6"
    echo "4. Назад"
    echo "=========================================="
    read -p "Выберите пункт меню [1-4]: " choice
    
    case $choice in
        1) disable_ipv6 ;;
        2) enable_ipv6 ;;
        3) status_ipv6 ;;
        4) main_menu ;;
        *) print_error "Неверный выбор"; pause; ipv6_menu ;;
    esac
}

disable_ipv6() {
    clear
    echo "=========================================="
    echo "  Отключение IPv6"
    echo "=========================================="
    
    print_warning "ВНИМАНИЕ: Отключение IPv6 может повлиять на сетевые соединения!"
    read -p "Продолжить? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Создаем backup
        cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)
        
        # Добавляем настройки отключения IPv6
        cat >> /etc/sysctl.conf << EOF

# Отключение IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        
        # Применяем настройки
        sysctl -p
        
        # Также отключаем IPv6 в GRUB
        if [ -f /etc/default/grub ]; then
            cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)
            sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' /etc/default/grub
            update-grub
        fi
        
        print_success "IPv6 отключен"
        print_message "Для полного применения изменений требуется перезагрузка системы"
        print_message "Резервные копии созданы: /etc/sysctl.conf.backup и /etc/default/grub.backup"
    else
        print_message "Операция отменена"
    fi
    
    pause
    ipv6_menu
}

enable_ipv6() {
    clear
    echo "=========================================="
    echo "  Включение IPv6"
    echo "=========================================="
    
    # Создаем backup
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # Удаляем настройки отключения IPv6
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
    
    # Убираем отключение IPv6 из GRUB
    if [ -f /etc/default/grub ]; then
        cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)
        sed -i 's/GRUB_CMDLINE_LINUX="ipv6.disable=1 /GRUB_CMDLINE_LINUX="/' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX="ipv6.disable=1"/GRUB_CMDLINE_LINUX=""/' /etc/default/grub
        update-grub
    fi
    
    # Применяем настройки
    sysctl -p
    
    print_success "IPv6 включен"
    print_message "Резервные копии созданы"
    print_message "Для полного применения изменений требуется перезагрузка системы"
    
    pause
    ipv6_menu
}

status_ipv6() {
    clear
    echo "=========================================="
    echo "  Статус IPv6"
    echo "=========================================="
    
    echo "Интерфейсы и их статус IPv6:"
    echo "----------------------------------------"
    ip -6 addr show | grep -E "inet6|global" 2>/dev/null || echo "IPv6 адреса не найдены"
    
    echo -e "\nПроверка доступности IPv6:"
    echo "----------------------------------------"
    if command -v ping6 &> /dev/null; then
        if ping6 -c 2 -W 1 google.com &> /dev/null; then
            print_success "IPv6 доступен"
        else
            print_warning "IPv6 недоступен или отключен"
        fi
    else
        print_warning "ping6 не доступен"
    fi
    
    echo -e "\nНастройки sysctl:"
    echo "----------------------------------------"
    sysctl -a 2>/dev/null | grep ipv6 | grep disable
    
    pause
    ipv6_menu
}

main() {
    check_root
    print_message "Запуск скрипта настройки VPS..."
    install_utilities
    main_menu
}

main
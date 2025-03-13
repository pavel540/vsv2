# Docker Vulnerability Scanner для Astra Linux

Инструмент для сканирования безопасности Docker контейнеров, специально разработанный для Astra Linux 1.7.6. Сканер проверяет контейнеры на наличие уязвимостей в операционной системе, зависимостях, программном обеспечении и анализирует Dockerfile на предмет проблем безопасности.

## Возможности

- Сканирование уязвимостей операционной системы контейнера
- Анализ зависимостей (Python, Node.js, PHP, Ruby)
- Проверка уязвимостей в программном обеспечении
- Анализ Dockerfile на предмет проблем безопасности
- Поддержка локальных и удаленных Docker хостов
- Интеграция с Trivy scanner
- Удобный веб-интерфейс для управления

## Требования

- Astra Linux 1.7.6 (рекомендуется) или совместимая операционная система
- Python 3.7 или выше
- Docker Engine
- Trivy scanner
- Доступ к интернету для обновления базы данных уязвимостей

## Установка

### Установка из репозитория

1. Клонируйте репозиторий:
```bash
git clone https://github.com/yourusername/docker-vulnerability-scanner.git
cd docker-vulnerability-scanner
```

2. Установите зависимости:
```bash
sudo apt-get install python3-pip
pip3 install -r requirements.txt
```

### Установка через пакет Debian

1. Установите необходимые инструменты для сборки:
```bash
sudo apt-get install build-essential devscripts debhelper dh-python python3-all python3-setuptools
```

2. Соберите пакет:
```bash
dpkg-buildpackage -us -uc -b
```

3. Установите собранный пакет:
```bash
sudo dpkg -i ../docker-vulnerability-scanner_1.0.0-1_all.deb
sudo apt-get install -f
```

## Использование

### Через командную строку

1. Сканирование контейнера:
```bash
docker-vuln-scan scan CONTAINER_ID
```

2. Сканирование удаленного контейнера:
```bash
docker-vuln-scan scan CONTAINER_ID --host tcp://remote-host:2375
```

3. Просмотр списка контейнеров:
```bash
docker-vuln-scan list
```

### Через веб-интерфейс

1. Откройте в браузере: http://localhost:5000
2. Выберите контейнер из списка
3. Нажмите "Сканировать" для начала проверки

## Конфигурация

Конфигурационный файл находится в `/etc/docker-vulnerability-scanner/config.yaml`:

```yaml
web_interface:
  host: 0.0.0.0
  port: 5000
  secret_key: your-secret-key
trivy:
  timeout: 300
  skip_update: false
```

## Лицензия

MIT License

## Автор

Ваше Имя <your.email@example.com>

## Поддержка

При возникновении проблем создавайте issue в репозитории проекта или обращайтесь по электронной почте. 
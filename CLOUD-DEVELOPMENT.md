# Облачная разработка Honeypot Grid

## Профиль разработки

Окружение связано только с mejustbox-byte/honeypot-grid, приватный доступ «Только я», без project secrets и пользовательских переменных. Выбранный стек: Python 3.14.7, uv 0.12.19, pytest 9.1.1, Ruff 0.16.10, setuptools 80.9.0. Сохранённые credentials платформы не следует читать или выводить; отсутствие project secrets не означает отсутствие платформенной аутентификации.

Используется код ветки feat/offline-manager-mvp, draft PR #2. Начальный снимок должен соответствовать проверенному commit, а не документационному 4220023. Не объединять PR при подготовке окружения. Новые задачи могут получить обновлённый checkout: сообщать фактический HEAD, выполнять offline uv sync --locked и повторять проверки при изменении lockfile. Изменения зависимостей требуют отдельного проверенного обновления снимка.

Первичная установка использует uv 0.12.19 из официального PyPI с hash verification (bootstrap мастера). В установочной фазе выполнить:

```sh
cd /workspace/honeypot-grid
bash scripts/cloud_setup.sh
```

Скрипт проверяет remote, устанавливает locked dependencies, прогревает build cache и выполняет все проверки offline. Не устанавливает Docker daemon, не меняет сетевую политику и не создаёт инфраструктуру. При блокировке package downloads использовать согласованный установочный этап либо заранее подготовленный cache; не обходить proxy/сетевые ограничения.

В восстановленной задаче:

```sh
cd /workspace/honeypot-grid
export PATH="$PWD/.venv/bin:/usr/bin:/bin"
export UV_CACHE_DIR="$PWD/.cloud-env/cache"
export UV_PYTHON_INSTALL_DIR="$PWD/.cloud-env/python"
export UV_PYTHON_BIN_DIR="$PWD/.cloud-env/bin"
uv sync --locked --offline
bash scripts/cloud_check.sh
```

Проверки: lint/format, pytest, документация, установленный CLI вне checkout, wheel/sdist и presence-only Docker/KVM report. Unit-тесты используют localhost и безвредные синтетические bytes; внешние адреса не сканируются. Никаких реальных samples, honeypot ingress или cloud credentials для разработки не нужно.

Сохранение install script не исполняет его и не подтверждает готовность файлового снимка. Требуется фактический успешный запуск в setup VM, Save/Republish и новая задача из опубликованной среды. Локальный PASS не заменяет эту проверку.

## Лабораторный профиль

Docker/KVM наличие диагностируется scripts/cloud_capabilities.py без обращения к daemon и без запуска VM. Даже наличие инструментов не подтверждает dedicated VM, отсутствие production routes, host credentials, enforcement или возможность вложенной виртуализации. Не создавать положительную VM attestation только по результатам presence checks.

Отдельный lab host нужен для Docker acceptance и disposable VM executor. Подготовка: выделенная Linux VM, cgroup v2, Docker, seccomp и AppArmor/SELinux; для будущего VM executor — поддерживаемая виртуализация, отдельные read-only образы без credentials, запрет сети, ограниченный storage и гарантированная очистка. Конкретные provider/account/region, бюджет и разрешённый scope должны быть заданы владельцем до создания платных ресурсов.

Отдельная лаборатория должна пройти реальные IPv4/IPv6 sentinel tests, crash recovery, TTL cleanup и orphan inventory checks из [RUNBOOK.md](RUNBOOK.md). Codex development environment нельзя автоматически считать такой лабораторией. Product deployment и публичный ingress не входят в настройку разработки.

## Обновление сохранённой среды

Settings → Codex Cloud → Environments → honeypot-grid → Edit. Проверить setup results, сохранить и Republish, затем запустить новую задачу и проверить HEAD/versions/exit codes. Если старый чат сообщает «Не удалось подтвердить статус публикации», открыть штатный Edit из Settings и проверить новый черновик; при сохраняющейся ошибке продолжить в исходном клиенте мастера. Не считать редактируемый текст успешно сохранённым снимком.

Официальный процесс: [OpenAI Cloud environments](https://learn.chatgpt.com/docs/environments/cloud-environments).

## Последняя попытка обновления, 2026-10-09

В setup VM получение product commit по GitHub HTTPS вернуло proxy 403. Подготовлен проверенный git bundle и передан штатным вложением для импорта в существующий checkout; это не изменение сетевой политики. Выполнение product install, сохранение нового filesystem и Republish ещё должны быть подтверждены. Docker executable/socket и cgroup обнаружены, KVM отсутствует; daemon и lab services не запускались. Bundle импортирован; первый product pytest run выявил зависимость теста ключа от umask. Fixture исправлена и локально проходят 84 теста при umask 0077. Для Cloud build отсутствует setuptools 80.9.0; официальный wheel передаётся отдельно с SHA256, сохраняется в .cloud-env/wheels и используется через UV_FIND_LINKS без включения сети. Повторный полный Cloud check и Republish пока ожидаются.

Новые данные о проверках записываются по результату, а не по намерению. Релизная готовность: [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).

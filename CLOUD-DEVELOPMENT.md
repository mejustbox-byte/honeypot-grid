# Облачная разработка Honeypot Grid

## Профиль разработки

Окружение связано только с mejustbox-byte/honeypot-grid, приватный доступ «Только я», без project secrets и пользовательских переменных. Выбранный стек: Python 3.14.7, uv 0.12.19, pytest 9.1.1, Ruff 0.16.10, setuptools 80.9.0. Сохранённые credentials платформы не следует читать или выводить; отсутствие project secrets не означает отсутствие платформенной аутентификации.

Рабочая ветка — main; продуктовые PR #2–#4 уже объединены. Первый alpha опубликован с неизменяемой привязкой к a59f6af82a471dde95ce1fcf058273b45c5f489b. Начальный снимок должен соответствовать проверенному commit, а не документационному 4220023. Подготовка окружения сама по себе не является разрешением на слияние. Новые задачи могут получить обновлённый checkout: сообщать фактический HEAD, выполнять offline uv sync --locked и повторять проверки при изменении lockfile. Изменения зависимостей требуют отдельного проверенного обновления снимка.

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

Отдельный lab host нужен для Docker acceptance и disposable VM executor. Подготовка: выделенная Linux VM, cgroup v2, Docker, seccomp и AppArmor/SELinux; для QEMU TCG executor — утверждённые kernel/initramfs и non-root lab user, отдельные read-only образы без credentials, запрет сети, ограниченный storage и гарантированная очистка. Конкретные provider/account/region, бюджет и разрешённый scope должны быть заданы владельцем до создания платных ресурсов.

Отдельная лаборатория должна пройти реальные IPv4/IPv6 sentinel tests, crash recovery, TTL cleanup и orphan inventory checks из [RUNBOOK.md](RUNBOOK.md). Codex development environment нельзя автоматически считать такой лабораторией. Product deployment и публичный ingress не входят в настройку разработки.

## Обновление сохранённой среды

Settings → Codex Cloud → Environments → honeypot-grid → Edit. Проверить setup results, сохранить и Republish, затем запустить новую задачу и проверить HEAD/versions/exit codes. Если старый чат сообщает «Не удалось подтвердить статус публикации», открыть штатный Edit из Settings и проверить новый черновик; при сохраняющейся ошибке продолжить в исходном клиенте мастера. Не считать редактируемый текст успешно сохранённым снимком.

Официальный процесс: [OpenAI Cloud environments](https://learn.chatgpt.com/docs/environments/cloud-environments).

## Проверенный снимок, 2026-10-09

Снимок продукта 71de6547c12feebfa7213afa423bac1ca6472fe1 установлен и полностью проверен в Cloud setup VM. Сохранены install/start инструкции, выполнены Save и Republish; UI подтвердил «Среда опубликована». Доступ «Только я», интернет выключен, project secrets и пользовательские переменные отсутствуют.

Проверки установки и offline startup завершились с exit 0: Python 3.14.7, uv 0.12.19, pytest 9.1.1, Ruff 0.16.10; 84 теста, lint/format, 13 документов и 42 локальные ссылки, установленный CLI и wheel/sdist. Новая задача восстановила тот же HEAD и версии; tracked/staged diff exit 0, offline sync exit 0. Полный cloud_check.sh завершился с exit 1: 81 тест прошёл, 3 tests/test_sensor.py упали с OSError при создании localhost-сокета 127.0.0.1. Полный PASS из setup VM не воспроизводится в изолированной задаче. Не пропускать эти тесты и не ослаблять сеть для получения зелёного статуса. Для socket integration требуется среда, где разрешён loopback. Оставшиеся проверки выполнены отдельно в новой задаче: документы 13/42, CLI вне checkout, offline wheel/sdist и presence-only report завершились с exit 0. Последующие изменения статуса в документации не изменяют опубликованный снимок 71de654.

После proxy 403 для GitHub HTTPS публичный код импортирован проверенным git bundle через штатное вложение. Официальный setuptools 80.9.0 wheel проверен по SHA256 и сохранён в .cloud-env/wheels для offline build. Сетевая политика не менялась. Тест прав ключа исправлен для umask 0077 без ослабления production проверки. Docker executable/socket и cgroup обнаружены, KVM отсутствует; daemon и lab services не запускались.

Новые данные о проверках записываются по результату, а не по намерению. Релизная готовность: [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).

## Новая реализация после опубликованного снимка

VM/delivery изменения проверяются отдельно; опубликованная среда остаётся на 71de654. В текущем local workspace проходят 129 тестов, включая localhost integration и parent-death. Это не повторная проверка в Cloud task и не обновление его filesystem snapshot. Изолированная задача ранее запрещала создание localhost-сокетов; новые socket integration tests также требуют loopback-capable среды. Local lab preflight завершился с exit 2: нет QEMU, Docker/socket, KVM и boot artifacts; аккаунт root. Для реального VM/Docker acceptance нужен отдельный non-root lab host с утверждёнными images/scope.

## Повторная проверка текущего main, 2026-10-09

Проверен checkout a175a559f4e625f3dd5351b602e559582478a701 в текущем рабочем контейнере: locked sync, Python 3.14.7, uv 0.12.19, 129 pytest tests, Ruff lint/format, 16 документов/60 локальных ссылок, CLI smoke, wheel/sdist, установка wheel и CLI вне checkout — PASS. Проверка ключа при umask 0077 и bash syntax checks также прошли. Для CLI smoke PATH должен включать .venv/bin, как в приведённой выше инструкции.

Это не проверка нового восстановления сохранённой Cloud-среды: её опубликованный снимок и прежние socket failures не считаются исправленными этим результатом. Presence-only preflight exit 2: Docker/QEMU/socket/KVM отсутствуют, аккаунт root, утверждённые boot artifacts отсутствуют. Реальные VM/Docker acceptance и stable gates остаются открытыми. Существующий alpha v0.1.0-alpha.1 опубликован; CI и release workflow для a175a55 завершились успешно.

## Отсутствие бюджета и отдельная лаборатория

Владелец подтвердил отсутствие бюджета на платное облако (2026-10-09).
Платные VM/подписки не создаются; подключение DigitalOcean для текущего этапа
не требуется. Подготовка собственного отдельного Linux-хоста и лабораторные
проверки переданы пользователю: [LOCAL-PC.md](LOCAL-PC.md).

Текущий рабочий контейнер не является lab host: CapEff/CapBnd равны нулю,
seccomp включён, cgroup v2 доступен только для чтения, Docker/QEMU отсутствуют.
Установка Docker не добавляет утраченные capabilities или право управлять cgroup.
Сохранённая Codex Cloud development-среда и выделенная лаборатория имеют разные
назначения. Отсутствие бюджета не меняет требования изоляции и стабильного выпуска.

# Стек разработки

## Решение

Выбран Python для offline manager, политик, нормализации и статического анализа метаданных. Небольшая команда получает один язык, зрелую библиотеку JSON/IP/криптографических примитивов и простой тестовый workflow. Enforcement сети и VM остаётся обязанностью runtime/инфраструктуры; Python не является sandbox.

| Область | Выбор | Обоснование и ограничения |
| --- | --- | --- |
| Runtime | CPython 3.14.x, Linux x86_64 | Поддерживаемая ветка с bugfix-обновлениями; точный patch фиксируется при проверке Cloud |
| Пакетный менеджер | uv, стабильный выпуск | Единый workflow, uv.lock; конкретная версия и lock будут проверены перед установкой зависимостей |
| Минимальный smoke | Стандартная библиотека Python | Нет зависимости от сети, package index или секретов |
| Тестовый стек | pytest; unittest для bootstrap smoke | pytest для unit/integration, синтетические fixtures; containment отдельно в лаборатории |
| Линтер/форматтер | Ruff | Один инструмент для lint и format; параметры в будущем pyproject.toml |
| Типизация | Python type hints; строгая проверка на следующем этапе | Без добавления второго языка до появления обоснованной необходимости |
| Контейнеризация | Linux OCI-контейнеры, Docker Engine в отдельной VM; Compose v2 для лаборатории | Минимум orchestration; rootless где доступно, без privileged/host namespaces |
| File sandbox | Отдельная одноразовая VM/microVM | Контейнерного ядра недостаточно для анализа недоверенных файлов |
| CI | GitHub Actions на Linux, минимальные read permissions | Smoke/docs → lint/types/unit → изолированные integration по мере появления кода |
| Хранение MVP | Локальные JSON-схемы и SQLite для состояния | Простая эксплуатация; production multi-tenancy требует отдельного решения |

MVP pins: CPython 3.14.7 (.python-version), uv 0.12.19, pytest 9.1.1, Ruff 0.16.10 (pyproject.toml и uv.lock). Runtime-зависимостей нет; lock включает dev tools и транзитивные зависимости с hashes. GitHub Actions checkout v4.2.2 и setup-python v5.6.0 закреплены на проверенные SHA в CI. Docker adapter использует только заранее одобренный локальный image digest; синтетический digest в примере не относится к реальному image. Не использовать floating latest images в будущей лаборатории.

## Альтернативы

Go подходит для агента хоста, но второй runtime пока увеличивает сопровождение; рассмотреть при измеренных требованиях к доставке агента. Kubernetes, брокер и PostgreSQL отложены до подтверждённой необходимости масштабирования. Web API, UI, LLM SDK и динамический анализ файлов не нужны для первого offline manager MVP.

## Политика зависимостей и CI

Первый smoke запускается без сторонних зависимостей. При добавлении pyproject.toml создавать проверенный uv.lock, обновлять через отдельный PR и использовать uv sync --locked в CI для проверки актуальности lock. При зависимостях проверять provenance, лицензии и известные уязвимости. Actions фиксировать на проверенные commit SHA; CI не получает deployment secrets и не запускает samples.

## Codex Cloud — критерии принятия

После фиксации этого документа создать отдельную среду только для mejustbox-byte/honeypot-grid. Не подключать другие repositories или production accounts. Setup не должен читать секреты, запускать приманки или открывать ingress. Установочный доступ к сети и сеть агента настраиваются отдельно; после setup для offline задач использовать отключённый доступ к интернету, если настройка доступна.

Проверка: подтвердить выбранный repository/branch и commit, Python 3.14.x, изолированный workspace, отсутствие настроенных project secrets, затем выполнить:

```sh
python3 scripts/smoke.py
```

Наличие временной управляемой платформой GitHub-аутентификации не равняется секретам проекта; не печатать env, токены или credential-файлы. Проверка secrets проводится через настройки среды и ограниченный аудит, без раскрытия значений. Абсолютное отсутствие любых платформенных credentials не заявляется.

Статус на 2026-10-09: отдельная среда только для honeypot-grid опубликована; восстановление в новой задаче и documentation smoke на commit 4220023e9cb458d94e4c80e7aa01481eaa3d8e70, Python 3.14.7 прошли. Project secrets и пользовательские переменные отсутствуют. Интернет выключен в настройках, но применение сетевой политики имеет статус unknown. MVP проверяется отдельно в ветке реализации. Сохранённый установочный скрипт среды закреплён на documentation commit: для перехода на новый commit потребуется обновление snapshot после review, без автоматического включения сети. Готовность реальной лаборатории не заявляется.

## Источники

- [Python version status](https://devguide.python.org/versions/)
- [uv locking and syncing](https://docs.astral.sh/uv/concepts/projects/sync/)
- [pytest](https://docs.pytest.org/en/stable/getting-started.html)
- [Ruff](https://docs.astral.sh/ruff/)

# Roadmap

Порядок этапов определяется containment, а не числом функций. Первый offline mock MVP реализован; реальная лаборатория и containment ещё впереди.

## Этап 0 — проектирование

- [x] Архитектура менеджера, runtime и потоков данных.
- [x] Threat model, требования egress deny и защиты от pivoting.
- [x] Privacy, sandbox, IoC и contribution guide.
- [x] Выбор стека зафиксирован в TECH-STACK.md.
- [x] Точные pins зависимостей и runtime проверены в отдельной Codex Cloud среде.
- [x] Cloud smoke и отсутствие project secrets подтверждены.
- [ ] Review архитектуры и модели угроз сопровождающим.

## Этап 1 — offline manager MVP

- [x] Типизированная конфигурация и явный scope.
- [x] Dry-run по умолчанию и mock provisioning adapter.
- [x] Конечный автомат, TTL, идемпотентность и аудит.
- [x] Human-in-the-loop: хеш плана, identity, expiry и одноразовость.
- [x] Unit-тесты негативных сценариев.

MVP identity пока является декларацией доверенного локального оператора; TTL reconciliation запускается явно. Реальный adapter и внешняя аутентификация отсутствуют.

Готовность: неправильная политика и подтверждение не запускают действие; всё работает на синтетических fixtures без облачного доступа.

## Этап 2 — изолированная лаборатория

- [ ] Выделенные VM и непривилегированные контейнеры.
- [ ] Egress deny IPv4/IPv6 и отдельные sensor segments.
- [ ] Синтетические SSH/HTTP-приманки без proxy/shell.
- [ ] Лимиты, stop работающего runtime и автоматический cleanup.
- [ ] Тесты sentinel: DNS, metadata, соседи, control plane и production substitute.

Готовность: независимый от приманки enforcement проходит containment и recovery tests; не остаются orphan resources.

## Этап 3 — телеметрия

Добавлен только bounded offline batch из синтетических нормализованных событий: allowlist полей, агрегация по дню и подавление групп <5. Production ingest/retention/HMAC ещё не реализованы.

- [ ] Bounded ingest, versioned schema и нормализация.
- [ ] Минимизация, keyed pseudonyms, retention и privacy review.
- [ ] Приватное хранилище, ACL и агрегированные метрики.
- [ ] Canary tests и безопасный экспорт.

Готовность: чувствительные синтетические поля не попадают в публикацию; переполнение и отказы не ослабляют политику.

## Этап 4 — sandbox и IoC

- [ ] Карантин файлов и статический анализ в одноразовой VM/microVM.
- [ ] Лимиты архивов, таймауты и уничтожение среды.
- [ ] Provenance, confidence, expiry и ручная проверка IoC.
- [ ] Профиль структурированного экспорта, затем оценка STIX-совместимости.

Готовность: нет сети/credentials в sandbox, образцы не покидают закрытое хранилище, экспорт проходит privacy review.

## Этап 5 — ИИ-анализ и эксплуатация

- [ ] Анализ только очищенных данных; provider interface и offline evaluation.
- [ ] Тесты prompt injection, доказательств и ложных выводов.
- [ ] Supply-chain checks, SBOM и CI для реализованных компонентов.
- [ ] Облачный adapter, бюджеты, runbooks и независимый security review.

Публичное развёртывание и динамический анализ файлов требуют отдельного решения после review; они не включены автоматически в MVP. Сроки и production readiness пока не заявляются.

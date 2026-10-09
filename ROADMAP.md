# Roadmap

Порядок этапов определяется containment, а не числом функций. Документация описывает требования; реализация ещё не начата.

## Этап 0 — проектирование

- [x] Архитектура менеджера, runtime и потоков данных.
- [x] Threat model, требования egress deny и защиты от pivoting.
- [x] Privacy, sandbox, IoC и contribution guide.
- [x] Выбор стека зафиксирован в TECH-STACK.md.
- [ ] Точные pins зависимостей и runtime проверены в отдельной Codex Cloud среде.
- [ ] Cloud smoke и отсутствие project secrets подтверждены.
- [ ] Review архитектуры и модели угроз сопровождающим.

## Этап 1 — offline manager MVP

- [ ] Типизированная конфигурация и явный scope.
- [ ] Dry-run по умолчанию и mock provisioning adapter.
- [ ] Конечный автомат, TTL, идемпотентность и аудит.
- [ ] Human-in-the-loop: хеш плана, identity, expiry и одноразовость.
- [ ] Unit-тесты негативных сценариев.

Готовность: неправильная политика и подтверждение не запускают действие; всё работает на синтетических fixtures без облачного доступа.

## Этап 2 — изолированная лаборатория

- [ ] Выделенные VM и непривилегированные контейнеры.
- [ ] Egress deny IPv4/IPv6 и отдельные sensor segments.
- [ ] Синтетические SSH/HTTP-приманки без proxy/shell.
- [ ] Лимиты, stop работающего runtime и автоматический cleanup.
- [ ] Тесты sentinel: DNS, metadata, соседи, control plane и production substitute.

Готовность: независимый от приманки enforcement проходит containment и recovery tests; не остаются orphan resources.

## Этап 3 — телеметрия

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

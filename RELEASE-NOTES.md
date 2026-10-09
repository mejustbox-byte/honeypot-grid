# Honeypot Grid v0.1.0-alpha.2

Второй предварительный выпуск для синтетической локальной Linux-лаборатории.
Python package version: 0.1.0a2; Git tag: v0.1.0-alpha.2. Это alpha, не заявление
о готовности к production или допуске недоверенных образцов.

Поставляются private policy/lifecycle CLI, mock и opt-in Docker network-none,
HMAC telemetry/retention, bounded sensor delivery с restart/replay protection,
opaque quarantine, opt-in QEMU metadata jobs/initramfs packer, offline analysis
и одноразовый reviewed synthetic export. Runtime dependencies отсутствуют.

Проверены локально: 129 pytest tests, Ruff lint/format, installed CLI, docs/link
smoke, wheel/sdist и fresh wheel install вне checkout. Реальные localhost
sensor-to-report и subprocess deadline/output/parent-death tests прошли.
VM/Docker adapter tests используют fake runners; реальный guest boot,
Docker delivery/containment и независимый TTL/inventory acceptance не выполнены.
Обновлены инструкции подготовки лаборатории пользователем и публичная документация.
GitHub Actions перед публикацией повторяет code checks и сборку на merge commit.

Пользователь выполняет локальные шаги из [LOCAL-PC.md](LOCAL-PC.md): подготовка
Linux VM/non-root lab user, vendor runtimes и approved images/scope, boot,
sentinel/failure/teardown/privacy acceptance. Образов, credentials, sample files
и готовой облачной инфраструктуры в release assets нет.

Известные ограничения: нет remote authentication, cloud provisioning,
утверждённого external ingress и подключённого LLM provider. Audit доверяет ОС;
attestation — утверждение оператора. Receipt-only sandbox-plan не подтверждает
сконфигурированный executor. Cloud development snapshot 71de654 отстаёт от этого
выпуска; в его isolated task три localhost socket tests падали. Не обходить эти
ограничения и не объявлять пропущенные проверки успешными.

Assets: wheel, sdist, SHA256SUMS и RELEASE-MANIFEST.json с commit, точными
tool versions, artifact hashes и test/limitations record. Manifest является
инвентарём выпуска, не независимым CVE audit или полным OS/container SBOM.
Перед установкой проверьте checksums. Rollback/stop и закрытая фиксация результатов
описаны в LOCAL-PC; stable gates — в [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).

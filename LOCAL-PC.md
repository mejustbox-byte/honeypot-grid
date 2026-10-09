# Что пользователю выполнить на локальном ПК

Первый выпуск v0.1.0-alpha.1 (Python package 0.1.0a1) предназначен для
синтетических лабораторных проверок. Он не подтверждает production containment.
Слияние и alpha-релиз разрешены владельцем с переносом проверок локальной
инфраструктуры в этот документ. Для стабильного релиза эти проверки обязательны.

## Лабораторная инфраструктура и ответственность пользователя

Лабораторная инфраструктура предоставляется пользователем. Можно использовать
собственный компьютер с отдельной Linux VM или выделенный Linux-хост.
Конкретный облачный провайдер не является обязательным.

Пользователь самостоятельно предоставляет отдельную Linux x86_64 VM или
выделенный lab host и выполняет пункты 1–7 ниже: устанавливает Docker/QEMU,
создаёт обычного lab-пользователя, проверяет отсутствие production/VPN/shared
folders/credentials, утверждает образы и закрытый scope, выполняет реальные
Docker delivery/isolation, QEMU boot/teardown, TTL/recovery и inventory checks.
QEMU TCG не требует KVM. Возможность запуска инструментов и loopback следует
проверить на выбранном хосте; установка пакетов сама по себе не доказывает изоляцию.

Сохраните приватные результаты и предоставьте только очищенный summary:
commit/tag, версии и hashes инструментов/образов, exit codes, pass/fail/not-run
по каждому acceptance gate и inventory после очистки. Не отправляйте ключи,
сырые captures, образцы или реальные адреса. До этих результатов сохраняется
alpha-статус; перенос работы пользователю не закрывает stable gates.

Если позже понадобится платное облако, перед созданием ресурсов отдельно
согласуются provider, регион, лимит расходов и срок удаления. Текущее разрешение
на разработку/слияние/релиз не разрешает автоматическое создание платных ресурсов.

## 1. Подготовить Linux-среду

Текущий CLI использует Linux/POSIX fcntl, memfd, prctl и фиксированные пути
Docker/QEMU. На Linux запускайте из обычного пользователя. На macOS или Windows
используйте отдельную Linux x86_64 VM; прямой запуск всего CLI на этих ОС не
поддержан. Docker Desktop сам по себе не подтверждает требуемый lab host.
KVM не обязателен для VM-адаптера: он использует QEMU TCG.

Не подключайте лабораторную VM к production/VPN/peering. Не добавляйте shared
home folders, cloud credentials, реальные captures или образцы. Для установки
инструментов используйте разрешённый установочный этап и официальные vendor
packages; после подготовки верните лабораторные сетевые ограничения.

Установите Git, CPython 3.14.7 и uv 0.12.19. Для Docker/VM acceptance отдельно
подготовьте /usr/bin/docker, /var/run/docker.sock, cgroup v2, seccomp и
AppArmor/SELinux; QEMU должен быть root-owned, non-writable, non-setuid
/usr/bin/qemu-system-x86_64 с seccomp support. Запускать sample VM от root нельзя.
Доступ к Docker socket равнозначен административному доступу к lab host;
предоставляйте его только доверенному управляющему пользователю.

## 2. Получить точную версию и выполнить обычные проверки

В новом рабочем каталоге Linux VM:

```sh
git clone https://github.com/mejustbox-byte/honeypot-grid.git
cd honeypot-grid
git checkout --detach v0.1.0-alpha.1
git status --short --branch
git rev-parse HEAD
python3 --version
uv --version
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -q
uv run --locked python scripts/smoke.py
uv run --locked python scripts/cli_smoke.py
uv build
```

Ожидаются 129 тестов без skips/failures, lint/format, проверка документов,
установленного CLI и wheel/sdist. TCP loopback 127.0.0.1 должен быть доступен.
Ошибка создания localhost socket означает непрошедший integration check;
не исключайте такие тесты и не называйте результат полным PASS.

Если скачали release wheel/sdist, сначала проверьте SHA256SUMS из того же
релиза (`sha256sum --check SHA256SUMS` в каталоге с assets), затем устанавливайте
wheel в отдельный Python 3.14.7 venv. Для разработки и fixtures нужен source
checkout. Приватные базы/ключи не поставляются в assets.

## 3. Проверить mock без запуска Docker/VM

```sh
umask 077
mkdir -m 700 lab-private
uv run --locked honeypot-grid --database lab-private/state.sqlite3 plan --config examples/lab.json --scope examples/scope.json > lab-private/plan.json
```

Просмотрите dry-run. Пример image digest фиктивный; он не является разрешённым
контейнерным образом. В [INSTALL.md](INSTALL.md) указаны approve/apply/status/
audit/stop/expire. Mock изменяет только приватное локальное состояние.
`--operator` опирается на доверие к ОС, не является удалённой аутентификацией.

## 4. Подготовить реальные lab images и закрытый scope

```sh
uv run --locked python scripts/lab_preflight.py
```

Exit 2 означает отсутствие предпосылок. Даже exit 0 не подтверждает isolation.
Зафиксируйте в закрытом журнале scope, owner, authorization_ref, версии и hashes
QEMU/kernel/initramfs/container, разрешённое окно и план emergency stop.
Attestation JSON заполняется только после реальной проверки host/routes/
credentials; шаблон с true сам по себе ничего не доказывает.

Соберите synthetic sensor image по [RUNBOOK.md](RUNBOOK.md) из утверждённого
immutable BASE_IMAGE, проверьте provenance/licenses и внесите реальный локальный
image ID в private config/scope. Runtime не делает pull. Public examples не
копируются в боевой scope без проверки.

Для QEMU подготовьте проверенные vendor boot files и kernel; используйте
[lab/README.md](lab/README.md) для guest-files manifest, deterministic initramfs,
private VM manifest/scope и vm-plan/approve/run. В первом тесте используйте лишь
безвредные opaque/ZIP fixtures. Не запускайте static_metadata на недоверенных
файлах на development host.

## 5. Выполнить Docker delivery и isolation acceptance

На выделенной VM создайте отдельный docker-none plan, просмотрите его и выдайте
одноразовый approval. Во всех lifecycle-командах одинаковые runtime/attestation
flags. Команды collect-docker и lab-probe приведены в RUNBOOK.

- Подтвердите network=none, UID 65532, read-only rootfs, capabilities/seccomp/MAC,
  resource limits и отсутствие host paths, runtime socket, ports/devices.
- Выполните lab-probe: 30 фиксированных TCP/UDP/DNS попыток к synthetic
  documentation-range адресам должны получить route denial. Это не подмена
  независимой проверки host/provider boundaries.
- Создайте только синтетические localhost соединения внутри sensor namespace;
  collect-docker должен доставить их в SQLite/report. Повтор snapshot не
  увеличивает счётчики; unknown fields/conflicting replay отклоняются.
- Проверьте outage/restart, квоту и retention/purge. Собирайте logs до
  stop/reconcile: удаление контейнера удаляет его локальный log buffer.
- Отдельно подтвердите IPv4/IPv6 deny к вашим утверждённым mock DNS/metadata,
  sibling/control-plane/production sentinels. Не тестируйте реальные production
  или cloud metadata endpoints и не открывайте внешний ingress.

## 6. Проверить VM teardown и независимый TTL

Для harmless fixtures подтвердите точные SHA256/size и отсутствие содержимого
или filenames в metadata. Проверьте bad hashes/nonce/schema, output flood,
busy loop, guest failure, deadline и уничтожение процесса при смерти родителя.
После каждой попытки проверьте отсутствие QEMU process, открытых input memfd и
writable persistent disks. Guest report не является независимой attestation.

Запустите Docker reconcile под независимым supervisor на lab host. Проверьте
остановку управляющего процесса и Docker, восстановление, фактический TTL,
emergency stop и отсутствие orphan containers/VM/disks/rules/identities. Один
bounded CLI loop не является гарантией teardown при отказе хоста.

## 7. Зафиксировать результаты и остановить лабораторию

В закрытом журнале храните tag/commit, runtime/image versions/hashes, время,
scope reference, exit codes, pass/fail/not-run по каждому пункту и inventory
после teardown. Не публикуйте IP, keys, credentials, raw logs или samples.
Публично допустим только очищенный summary. Приватные backup/snapshot copies
имеют отдельный retention; SQL purge не удаляет их автоматически.

До стабильного выпуска остаются actual lab acceptance, supply-chain/SBOM и
независимый security review; cloud provisioning, внешняя auth и ingress ещё не
поставляются. См. [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).
Чтобы откатить alpha, остановите его runtime, проверьте inventory и используйте
отдельное новое рабочее состояние; не удаляйте базы/образцы без review retention.

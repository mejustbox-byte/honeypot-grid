# Модель угроз

## Scope

Защищаем хосты, control plane, облачный аккаунт, ключи, данные наблюдений и получателей публичных отчётов. Недоверенными считаются входящий трафик, события, файлы, результаты парсеров, зависимости и вывод ИИ. Компрометация приманки ожидаема.

Оператор и система выдачи подтверждений доверенные, но их ошибки учитываются. Уровень защиты от компрометации гипервизора/облачного провайдера ограничен; полная неуязвимость не заявляется. Таблица описывает целевые требования; степень текущей проверки приведена ниже.

## Угрозы и проверки

| Угроза | Защита | Критерий проверки |
| --- | --- | --- |
| Pivoting из приманки | Отдельные сегменты, отсутствие маршрутов, host и cloud deny | Нет доступа к соседнему sensor, control plane и синтетическому production sentinel |
| Reverse connection, DNS exfiltration | Egress deny, отсутствие DNS, фильтрация обоих IP семейств | Запрещены новые соединения TCP/UDP и DNS к лабораторным sentinel |
| Доступ к cloud identity | Нет credentials; metadata заблокирован | Из приманки и sandbox нет доступа к симулятору metadata |
| Container escape | Выделенная VM, без host mounts/socket, MAC/seccomp | Конфигурационный тест запрещает privileged и host namespaces |
| Подмена образа | Digest, provenance и dependency review | Неутверждённый digest отклоняется |
| Захват менеджера через event | Схемы, ограниченные поля, отсутствие shell/tools | Payload с инструкциями не меняет план и политику |
| Повтор подтверждения | Identity, TTL, одноразовый approval, хеш плана | Старое, повторное и чужое подтверждение отклоняются |
| Отказ в обслуживании | Квоты, rate limit, bounded queue, CPU/memory/disk limits | Перегрузка не снимает deny и не блокирует stop |
| Утечка телеметрии | Минимизация, ACL, retention, privacy review | Синтетические чувствительные canary-поля отсутствуют в экспорте |
| Повторная идентификация | Укрупнение времени, подавление редких групп | Малые группы не экспортируются; review отмечает residual risk |
| Вредоносный файл/архив | Отдельная VM, статический анализ, лимиты распаковки | Безвредные fixtures проверяют traversal, вложенность и timeout |
| Опасный IoC | Provenance, confidence, срок, review | Неподтверждённый индикатор не публикуется автоматически |
| Остаточные ресурсы | TTL, идемпотентный cleanup и inventory reconciliation | После teardown отсутствуют VM, диски, правила и привязки, кроме разрешённого аудита |

## Политика тестов

Все адресаты проверок — синтетические sentinel в разрешённой лаборатории. Не тестировать реальные production, metadata или сторонние сервисы. Для проверки запретов использовать безопасные попытки соединения и конфигурационные assertions, без exploit chains или weaponized samples.

Тестировать IPv4 и IPv6, restart runtime, восстановление после отказа, потерю enforcement и заполнение хранилища. Если IPv6 выключен, тест должен подтвердить невозможность включить его из приманки. При отказе policy/audit новые действия блокируются. Emergency stop проверяется на уже работающем экземпляре.

## Остаточные риски и инциденты

Остаются ошибки ядра/парсеров, supply-chain риск, злоупотребление разрешённым каналом ответов и ошибки обезличивания. Компрометированная приманка может отправлять данные в ответы на разрешённые входящие соединения; поэтому в ней не должно быть чувствительных данных.

При подозрении на нарушение containment: закрыть ingress/egress, остановить provisioning, изолировать runtime, сохранить минимально необходимые доказательства в закрытом хранилище, отозвать затронутые идентичности и провести review перед восстановлением. Нельзя публиковать raw logs или образцы. Сообщения об уязвимостях — по [SECURITY.md](SECURITY.md).

Изменения сетевых исключений, runtime, sandbox, схемы экспорта или возможностей ИИ требуют обновления этой модели до включения функции.

## Проверенное поведение и непроверенные границы

129 локальных тестов покрывают scope/plan rejection, approval/TTL, concurrency/restart, приватные файлы и квоты, clock rollback, HMAC/retention, canary fields, review tampering/replay, archive metadata и bounded localhost sensors. Fake Docker runner проверяет argv, security/ownership drift, компенсирующую очистку и recovery. Аудит mock effect атомарен; Docker effect журналируется до исполнения и компенсируется при ошибке.

Сырой JSON ограничен 16 KiB; дубликаты ключей и non-finite значения запрещены. HMAC key хранится отдельно от git; ключ и база требуют 0600, карантин 0700. Rotation использует явный epoch. Purge запускается явно, поэтому snapshots/backups и их retention требуют отдельного контроля.

Scope, OS identity, checkout, база и администратор доверены. Высокая отметка времени блокирует откат в нормальных действиях, но владелец ОС может изменить базу; она не криптографически защищённый аудит. Docker ownership labels и inspection защищают от случайного чужого teardown, не от захваченного daemon/host.

Никакой реальный сетевой/VM enforcement этими тестами не доказан. VM attestation не создаёт dedicated host. Docker stdout собирается явной командой collect-docker, включая bounded polling; source не собирается и имеет отдельный HMAC-domain. Проверен localhost sensor → envelope → SQLite → report; Docker ingestion проверен fake runner. QEMU executor реализован, но untrusted samples запрещены до лабораторной boot/containment acceptance. Offline rules и model proposal validator не являются подключённым LLM.

Псевдонимизация и подавление малых групп не исключают повторную идентификацию. Экспорт требует локального одноразового privacy review; approval stdout может потеряться после потребления и не должен повторно воспроизводиться. Вывод внешней модели не исполняется и не меняет сетевые политики.

Release/containment gates: [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md). Development preparation: [CLOUD-DEVELOPMENT.md](CLOUD-DEVELOPMENT.md). Независимый supervisor TTL и реальный orphan inventory обязательны до лабораторного ingress.

## Новые границы VM и доставки

Доставка использует versioned envelope с delivery_id и пяти-полевым минимальным sensor event. IP не собирается и не выдумывается: source хранится как отдельный HMAC-domain «source-uncollected». Private SQLite атомарно подтверждает envelope и событие, повторы с изменённым содержимым отклоняются. Ограничены framing, очередь и число событий. Канал stdout/локальный collector не аутентифицирует удалённый sensor; Docker сборщик обязан проверить ownership и runtime security перед чтением bounded logs.

VM executor opt-in на выделенном Linux lab host. Hash-bound одноразовое approval включает kernel/initramfs, scope, sample и фиксированную политику. Kernel/initramfs — утверждённые доверенные boot artifacts, samples передаются только opaque raw read-only диском. QEMU запускается без NIC, host mounts, monitor, credentials и shell; TCG не требует KVM. Host не парсит sample. Guest парсит лишь bounded metadata и возвращает nonce/hash-bound строго ограниченный результат. Runtime имеет deadline, output cap, process-group cleanup и parent-death signal; verified boot, artifact provenance, реальный teardown и hypervisor hardening остаются обязательными лабораторными проверками. Не считать fake runner или отсутствие NIC-флага доказательством реальной изоляции.

# Мессенджер ThePost: Matrix как основа — исследование

Исследование 17.11.2026. Постановка владельца: мессенджер, нативно интегрированный в Postman; **отчуждаемый
самостоятельный продукт**; часть функций можно выкинуть; ВКС — отдельный продукт на Rust-крейтах. Подход выбран
владельцем 17.11: **Matrix** (рассматривавшаяся собственная JMAP-модель отклонена). Номера в скобках — источники
в конце; факты по Postman — из его репо (ADR 0012, карточка CH-05).

**Итог.** Клиентская часть уже готова: в Postman есть канал Matrix (CH-05, done) поверх `matrix-sdk` 0.19.1 —
вход паролем и SSO через браузер, sync с курсором, история, серверный поиск, файлы, E2EE (`vodozemac`),
верификация, бэкап ключей; канал — только протокол, общие механизмы в ядре (ADR 0012). Строить нужно **сервер**:
homeserver на готовой Rust-базе (не Synapse: AGPL-3.0 конфликтует с проприетарной лицензией ThePost; не свой
сервер на ruma — годы). Кандидаты: **Tuwunel** (зрелость) и **Palpo** (наш стек: PostgreSQL, MSC3861, RTC) —
решить bake-off на бета-стенде. ВКС — «влить протокол, развести медиа»: сигнальный слой (Matrix RTC, MSC4143)
в homeserver, SFU отдельным сервисом; Rust-SFU с LiveKit-протоколом существуют (mediacore, livekit-rs) — пилот
против эталона livekit-server.

## 1. Как делают другие

| Система | Идентичность | Хранение | Транспорт | Комплаенс |
|---|---|---|---|---|
| M365 Teams | UPN = email | сообщения в скрытых папках mailbox'ов Exchange (Substrate) | SignalR WS; presence — отдельная служба | journaling, eDiscovery через Exchange |
| Google Chat | аккаунт Workspace | своё хранилище; поиск/retention через Vault | WS в клиенте | Vault |
| XMPP (RFC 6120/6121) | JID | MAM (XEP-0313) | XML-стримы, федерация | стороннее |
| Matrix | MXID | homeserver (full history) | `/sync`; федерация по договору | зависит от сервера; E2EE vs retention |

Вывод: в корпоративных экосистемах идентичность мессенджера = учётка почты; федерация вторична (Teams её
фактически нет). Matrix отличается готовым открытым протоколом, зрелыми клиентами и Rust-реализациями сервера.

## 2. Клиент: в Postman уже встроен

- `crates/backend-matrix` (CH-05, статус done; ручная проверка пройдена): `matrix-sdk` 0.19.1, E2EE `vodozemac`,
  вход пароль/SSO (браузер, loopback), sync с `since`, догон от курсора, файлы (и шифрованные), серверный поиск,
  `matrix.to`-ссылки. Ограничения протокола честно отражены в договоре канала.
- ADR 0012: канал = только протокол (`ChannelPlugin`); хранение, поиск, счётчики, уведомления — ядро. Мосты —
  не в клиенте.
- Клиент сервероагностичен: подключится к любому homeserver, говорящему Client-Server API. Поэтому выбор
  сервера проверяется дёшево.

Остаток «встройки» — швы, не клиент: сервер (п. 3), идентичность (п. 4), автообнаружение (`.well-known/matrix/client`
на почтовом домене → `chat.<домен>`, чтобы пользователь не вводил адрес руками), E2EE-политика (п. 5).

## 3. Серверная база (главное решение)

Миграций между homeserver'ами нет — выбор = коммитмент.

| | Synapse | **Tuwunel** | **Palpo** | Continuwuity |
|---|---|---|---|---|
| Язык/лицензия | Python / **AGPL-3.0** | Rust / Apache-2.0 | Rust / Apache-2.0 | Rust / Apache-2.0 |
| Зрелость | эталон | полный день, «официальный преемник conduwuit», деплой для граждан Швейцарии | 10 мес (создан 2026-01-18), комьюнити (142★), без продакшн-деплоев; README сам признаёт Tuwunel «значительно зрелее» | комьюнити-продолжение conduwuit |
| Данные | PostgreSQL | RocksDB (встроенная) | **PostgreSQL 16+** (Diesel) | RocksDB |
| Спека | полная | «всё кроме нишевого» | Complement 672/0/14 | как conduwuit |
| Аутентификация | OIDC/SAML/CAS + модули | upstream OIDC-IdP, встроенный OIDC-сервер (MAS), LDAP, JWT, тонкие правила логина | upstream OIDC, LDAP, JWT, **MSC3861 делегированная OIDC** (локальные пароли выключаются — модель «одна учётка ThePost») | проверять |
| Прочее для нас | — | — | `retention`, `well_known`, **RTC-discovery (MSC4143, бэкенды LiveKit)**, **нативный слайдинг-синк (sync v3)** — Element X работает | — |

AGPL-3.0 (Synapse; также все готовые веб-клиенты и lk-jwt-service) — не запрет: **немодифицированный** деплой
правомерен, включая закрытый контур; модификация/форк = обязанность открыть код изменений. Для проприетарного
ThePost это означает: Synapse отпадает как база для упаковки; готовые AGPU-компоненты — только как есть.

**Рекомендация: bake-off Tuwunel vs Palpo** на бета-стенде (клиент Postman уже готов — испытание дёшевое).
Протокол: чек-лист ручной проверки CH-05 (вход пароль/SSO, sync, E2EE, файлы, поиск на сервере) против каждого;
сценарий провижининга через admin API; поведение под нагрузкой; бэкап/восстановление (RocksDB-каталог vs
PostgreSQL — уже знакомая процедура); наличие RTC-discovery. Continuwuity — запасной, в bake-off не ведём.

## 4. Интеграция с ThePost (швы)

1. **Идентичность**: одна учётка. Механизмы у кандидатов: OIDC upstream, LDAP, JWT, MSC3861-делегирование
   (Palpo). ThePost сегодня не OIDC-провайдер — вопрос владельцу (п. 6.2).
2. **Провижининг**: тонкий крейт-мост на стороне ThePost (условно `tp-mxsync`): события шины (создание/
   блокировка учёток, оргструктура) → admin API homeserver'а: создание/заморозка пользователя, displayname из
   orgchart, начальные пространства подразделений. Клей, не сервер.
3. **Автообнаружение**: `.well-known/matrix/client` на почтовом домене.
4. **Комплаенс**: E2EE-комнату сервер не читает — серверный поиск и журналирование для неё невозможны. Политика
   по умолчанию — решение владельца (п. 6.3).
5. **Федерация**: закрытый контур по умолчанию; включение — решение владельца (п. 6.4).
6. **Мобильный компаньон** (вне Postman): Element X + push-шлюз sygnal — опция продукта (п. 6.5).

## 5. ВКС — решено владельцем 17.11: «влить протокол, развести медиа»

Сигнальный слой (membership-события, MSC4143 discovery) — в homeserver в любом случае (у Palpo конфиг `rtc`
есть, у Tuwunel — проверить в bake-off). Отдельно — медиа-плоскость (SFU) и клиент звонков.

Решения владельца: закрытый контур, веб-клиент нужен; SFU вынести для горизонтального масштабирования; клиент
звонков — свой UI в Postman, но другие клиенты тоже должны работать (⇒ SFU обязан говорить протоколом LiveKit);
E2EE-звонки — опция через админ-политику/GPO (в Postman есть механизм policy keys, решение 2026-11-12 — ключи
вида `CallPolicy`); масштаб v1 малый (~30 участников/комната).

### 5.1 Каталог Rust-SFU (критерий: LiveKit-протокол = интероп с Element Call и др.)

| Проект | Лицензия/зрелость | LiveKit-протокол | Кластер | Вердикт |
|---|---|---|---|---|
| **mediacore** (str0m) | MIT; 87 коммитов, 1★, одна компания; пуш 2026-10-21 | да: сигналинг + room API, интероп-тесты против CLI/Node-SDK LiveKit | да, multi-node + PostgreSQL | главный кандидат пилота |
| **livekit-rs** | Apache-2.0; создан 2026-10-22, 0★ | да: цель «полная совместимость с livekit-server v1.13.10» (сигналинг, JWT, Twirp, webhooks) | нет (single-node, без Redis/БД) | второй LiveKit-совместимый, совсем зелёный |
| **videocall.rs** | Apache-2.0; 1811★, с 2022, активен | нет — свой сигналинг и клиенты | своя архитектура | самый зрелый чисто-Rust; ценой интеропа |
| livekit-server (Go) | Apache-2.0, production | эталон | да | fallback и эталон приёмки |
| waterbus-rs | Apache-2.0, 20★ | частично | — | пуш 2025-08 — выпал |
| mediasoup (крейт) | Rust-API над C++-движком | нет | — | движок, ядро не Rust |

Своё (если оба кандидата не пройдут): `str0m` + `oxpulse-sfu-kit` + крейт `livekit-protocol` (Apache-2.0) —
сигналинг LiveKit открыт, совместимость достижима без Go. `rheomesh` (beta), `webrtc-rs/sfu` — материал.

**E2EE-звонков нет ни у одного Rust-кандидата** — главный пункт приёмки пилота (в Element Call E2EE реализовано
клиентски поверх LiveKit E2EE; проверить совместимость).

### 5.2 Обвязка ВКС

- **Мост Matrix ↔ LiveKit**: lk-jwt-service (element-hq, Rust, AGPL-3.0, активен) — выдаёт LiveKit-токены по
  membership комнаты. Деплой немодифицированным правомерен; при доработке — переписать (мал) или открыть код.
- **Клиент звонков в Postman**: свой, из Apache-кусков — `matrix-sdk` + livekit-rust-sdk; membership-логика
  Matrix RTC проста. Готовый `matrix-rust-rtc` (AGPL-3.0) в проприетарный Postman **линковать нельзя** — только
  референс.
- **Веб-клиент**: Element Web / Cinny / Hydrogen — все AGPL-3.0, немодифицированный деплой правомерен,
  ребрендинг-форк = открыть код; свой тонкий клиент позже возможен на matrix-js-sdk (Apache-2.0).

## 6. Вопросы владельцу (issue «решение»)

1. **База homeserver** — решено владельцем 17.11: испытывать **Palpo первым**; если устраивает по чек-листу
   CH-05 и провижинингу — Tuwunel не тестировать и брать Palpo (PostgreSQL, MSC3861, retention, RTC,
   нативный слайдинг-синк). Tuwunel — запасной путь при провале Palpo.
2. **Мост идентичности** — уточнено владельцем 17.11: **OIDC будет у заказчика** — свой провайдер не строить,
   поддержать на обеих сторонах (клиент Postman и сервер). По умолчанию **LDAP** (у Postman уже есть
   backend-ldap, у Palpo LDAP есть); поддержка upstream OIDC — требование к базе, у Palpo есть.
3. **E2EE комнат по умолчанию**: обычные (поиск и журнал работают) с E2EE опционально — по умолчанию так;
   альтернатива — E2EE везде, поиск/журналирование только для обычных.
4. **Федерация Matrix**: закрытый контур (по умолчанию) или включить.
5. **Мобильные клиенты и push** — детально в п. 6.1.

### 6.1. Мобильные клиенты и push (детали к п. 6.5)

**Какие клиенты будут работать с Palpo** (критично одно: слайдинг-синк — у Palpo нативный sync v3 есть):

| Клиент | Платформы | Лицензия | Состояние |
|---|---|---|---|
| Element X | Android, iOS | AGPL-3.0 | флагман Element, оба активны (пуши сегодня) |
| SchildiChat | Android | AGPL-3.0 | форк Element X, активен (11.2026) |
| FluffyChat | Android, iOS, десктоп | AGPL-3.0 | активен (3306★), свой UI |
| Element (классический) | Android, iOS | — | EOL, заменён Element X |

Все AGPL-3.0: немодифицированные — правомерно, ребрендинг = открыть код.

**Push.** Matrix-push = homeserver → push-шлюз (sygnal) → платформа (FCM/APNs). Варианты:
- **Android без Google**: Element X официально поддерживает **UnifiedPush** ([issue #4256](https://github.com/element-hq/element-x-android/issues/4256),
  [доки Element](https://docs.element.io/latest/element-support/element-androidios-client-settings/using-unified-push-and-ntfy-for-push-notifications)):
  ставится дистрибьютор (ntfy; сервер ntfy — свой, в контуре) — push полностью без учёток Google.
- **Android с FCM**: сторовая сборка Element X пользуется шлюзом Element — от организации ничего не нужно,
  но трафик идёт через инфраструктуру Element (внешний контур, метаданные). Свой путь: Firebase-проект
  (бесплатный, оплаты не требует) + свой sygnal.
- **iOS**: только APNs, альтернатив нет. Сторовое Element X использует APNs-ключи Element — организации ничего
  не нужно (внешняя зависимость); свой брендированный клиент = учётка Apple Developer ($99/год).
- Без дистрибьютора/учётки вообще — фоновой доставки нет: уведомления только при открытом приложении.

**Учётки из РФ.**
- Учётка Matrix — выдаёт наш сервер, сторонние не нужны. Google-учётка пользователю не нужна
  (UnifiedPush). Apple ID — только для установки из App Store (обычный RU Apple ID; доступность App Store
  в РФ в целом есть, [перебои 07.2026](https://meduza.io/feature/2026/07/20/u-chasti-zhiteley-rossii-perestal-rabotat-app-store-roskomnadzor-blokirovku-otritsaet) — РКН блокировку отрицает).
- Организации: Firebase (FCM) — бесплатный тариф, из РФ регистрируется без оплаты; Apple Developer $99/год —
  оплата из РФ затруднена (карты не проходят) — ограничение только для своего iOS-клиента; публикация в
  Google Play $25 разовая — необязательна, APK можно раздавать через MDM.
- Суверенный вариант: свой sygnal + свой сервер ntfy — push без Google/Apple-учёток организации (Android);
  iOS суверенно не решается — только APNs.

**Рекомендация v1 — принята владельцем 17.11**: Element X как есть; Android — UnifiedPush + свой ntfy; iOS —
APNs через ключи Element (принять внешнюю зависимость) или без мобильного iOS в v1. Свой мобильный клиент
пока не делаем — вернуться после запуска, вместе с брендированным веб-клиентом.

## 7. Риски

- Palpo/Tuwunel: выбор без пути отката (миграций нет) — сглаживается bake-off на реальном чек-листе.
- mediacore/livekit-rs: молодость, шина-фактор; E2EE не подтверждён — пилот обязателен, fallback livekit-server (Go) или videocall.rs (цена интеропа).
- AGPL-граница: компоненты правомерны только немодифицированными — держать перечень и не патчить.
- Веб-клиент без ребрендинга — продукт «как есть»; брендинг = свой тонкий клиент на matrix-js-sdk (отдельная работа).

## Источники

1. Tuwunel — https://github.com/matrix-construct/tuwunel
2. Конфигурация Tuwunel (аутентификация) — https://raw.githubusercontent.com/matrix-construct/tuwunel/main/tuwunel-example.toml
3. Palpo — https://github.com/palpo-im/palpo (конфиги: `crates/server/src/config/{oidc,ldap,jwt,delegated_auth,rtc}.rs`)
4. Continuwuity — https://continuwuity.org/, зеркало https://github.com/continuwuity/continuwuity
5. Synapse (лицензия AGPL-3.0) — https://github.com/element-hq/synapse
6. This Week in Matrix — https://matrix.org/blog/2026/03/20/this-week-in-matrix-2026-03-20
7. Element Web — https://github.com/element-hq/element-web; Cinny — https://github.com/cinnyapp/cinny; Hydrogen — https://github.com/element-hq/hydrogen-web
8. lk-jwt-service — https://github.com/element-hq/lk-jwt-service
9. matrix-rust-rtc — https://github.com/BillCarsonFr/matrix-rust-rtc
10. Element: MatrixRTC / Element Call на LiveKit — https://element.io/blog/exploring-matrixrtc-real-time-communication-in-rooms
11. mediacore — https://github.com/GlobalArtInc/mediacore
12. livekit-rs — https://github.com/livekit-rs/livekit-rs
13. videocall.rs — https://github.com/security-union/videocall-rs
14. str0m — https://github.com/algesten/str0m; oxpulse-sfu-kit — https://github.com/anatolykoptev/oxpulse-sfu-kit; rheomesh — https://github.com/h3poteto/rheomesh; webrtc-rs SFU — https://github.com/webrtc-rs/sfu
15. Перепись LiveKit-server на Rust (заброшена) — https://community.livekit.io/t/livekit-implementation-in-rust/1612
16. MSC4143 (RTC discovery), MSC3861 (делегированная аутентификация) — matrix.org docs
17. Postman: ADR 0012 «Каналы бесед», карточка CH-05, ручная проверка CH-05 (репо Dicobraz421/Postman)
18. srvPost: CLAUDE.md (правила), решение 2026-10-31 «готовое вместо своего», решение 14.11 «сначала изучить практику»

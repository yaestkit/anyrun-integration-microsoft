# asyncv2: обоснование изменений для ревью

## 1. Цель

Эта папка — полная версия `Microsoft Defender for Endpoint` для отдельной
тестовой ветки `asyncv2`. За основу взята полная сборка
`MDE-full-folder-replacement-2026-09-29`; поверх неё изменён только runtime
Sandbox и необходимые ему шаблоны, тесты и документация. Исходный код TI Feeds
не менялся.

Задача `asyncv2` — одновременно решить две проблемы:

1. не держать HTTP-вызов Logic App открытым во время Live Response и анализа
   ANY.RUN, то есть не возвращать старую проблему с HTTP timeout;
2. не завершать Logic App сразу после `202 Accepted`, а показать в истории её
   запуска понятные этапы: файл отправлен, задача ANY.RUN создана, вердикт
   получен либо обработка завершилась ошибкой.

## 2. Что было до изменения

Первая асинхронная версия уже правильно отделяла долгую работу от HTTP:

- HTTP Function принимала запрос и ставила сообщение в Storage Queue;
- queue-triggered worker выполнял Live Response и ожидал ANY.RUN;
- Logic App получала `202` примерно за несколько секунд.

Это устраняло сетевой timeout, но Logic App считала свою работу законченной в
момент постановки сообщения в очередь. Оператор видел только `job_id` и должен
был переходить в Application Insights, чтобы выяснить, был ли действительно
получен файл, начался ли анализ и какой вердикт вернулся.

## 3. Выбранная схема

```text
Logic App
   |
   | POST (короткий вызов)
   v
Starter Function -----> private status blob: queued
   |
   v
Storage Queue
   |
   v
Worker Function ------> status: collecting/submitted/waiting/completed|failed
   |
   +---- Live Response / Blob evidence
   +---- ANY.RUN analysis
   +---- Defender comments and indicators

Logic App ---- POST Status Function every 15/30 s ----> status blob
```

Starter всё ещё отвечает `202 Accepted`; долгой HTTP-сессии нет. Logic App
проверяет состояние отдельными короткими запросами и поэтому остаётся видимым
оркестратором, а не исполнителем долгой операции.

## 4. Что изменено и почему

### 4.1. Хранилище состояния задания

Добавлен `src/anyrun_mde_core/job_status.py`.

- Состояние хранится в отдельном private blob container
  `anyrun-job-status`.
- Имя blob — проверенный `job_id`; произвольный путь передать нельзя.
- Запись содержит `state`, `stage`, безопасные метаданные анализа, время и
  короткую историю переходов.
- История ограничена последними 50 переходами, чтобы blob не рос бесконечно.
- Для terminal state добавляется `completed_at`.

Blob Storage выбран потому, что он уже обязателен для Function App и очереди.
Новый Cosmos DB, Table Storage, Service Bus или Durable Functions увеличили бы
стоимость, права и сложность развертывания без необходимости для небольшого
JSON-документа на один запуск.

### 4.2. Starter Function

`ANYRUN-Sandbox-MDE-FA/anyrun_connector.py` теперь:

- создаёт status record `queued` до передачи работы worker;
- повторяет эту безопасную pre-enqueue запись до трёх раз с короткой задержкой;
- возвращает `job_id` и `state: queued`;
- не ставит сообщение в очередь, если tracking record создать не удалось.

Повтор безопасен: `job_id` уже зафиксирован, `create()` перезаписывает тот же
status blob, а queue output устанавливается только после успешной записи. Это
сглаживает кратковременный Storage 503/connection reset, не создавая вторую
задачу. Постоянная ошибка по-прежнему возвращает 500: Logic App не должна
принять задание, состояние которого потом невозможно проверить.

### 4.3. Worker Function

`ANYRUN-Sandbox-MDE-Worker/worker.py` публикует переходы состояния и в конце
записывает либо полный массив `analyses`, либо безопасное описание ошибки.

Запись статуса является observability side channel и не управляет бизнес-
операцией. Начальный и промежуточные статусы записываются с ограниченными
повторами, но окончательный сбой Blob не прерывает уже начатый анализ. Для
`completed` и `failed` используется больше попыток. Если результат уже добавлен
в Defender, но `completed` так и не удалось сохранить, worker завершается без
poison message: ручной replay мог бы создать повторную платную задачу. В таком
случае worker пишет явное предупреждение в Defender alert и Function logs.

Повторы ограничены не только числом попыток, но и временем: 10 секунд для
progress status и 30 секунд для terminal status. Встроенные повторы Azure Blob
SDK для status client отключены, а connect/read timeout ограничены 3/5
секундами. Это не позволяет каскаду SDK retry и application retry съесть
90-минутный бюджет worker во время деградации Storage.

Queue-level retry оставлен равным одному запуску. Это сознательное решение:
после успешного `run_file_analysis` повтор всей queue-функции может создать
дубликат платной задачи ANY.RUN. Узкие безопасные повторы сохранены внутри
Defender-клиента: например, новый Machine Action может кратковременно отвечать
`404 ResourceNotFound`, и этот конкретный read-запрос повторяется без создания
нового анализа.

Если worker падает, он:

- переводит status в `failed`;
- добавляет best-effort комментарий в Defender alert;
- повторно выбрасывает исключение, чтобы Azure поместил сообщение в poison
  queue и сохранил корректную техническую диагностику.

Если ни один file/URL не удалось передать в ANY.RUN, задача завершается ошибкой,
а не ложным `completed`.

### 4.4. Безопасные данные о ходе анализа

`processor.py` сообщает следующие этапы:

- `collecting_evidence`;
- `evidence_collected`;
- `submitting_to_anyrun`;
- `submitted_to_anyrun`;
- `waiting_for_verdict`;
- `analysis_completed`.

В status допускаются только данные, полезные оператору:

- basename файла либо URL без query string и fragment;
- SHA-256 файла;
- UUID и ссылка задачи ANY.RUN;
- verdict и threat score;
- количество принятых и отклонённых IOC.

Не сохраняются API key, client secret, access token, содержимое файла, Storage
Account key и SAS query string. Для alert с несколькими evidence итог содержит
массив `analyses`, поэтому результат первого объекта не затирает остальные.
Тексты исключений проходят через единый sanitizer из `anyrun_mde_core.utils`
до записи в status, Function logs, Logic App `runError` и комментарии Defender,
включая evidence-specific комментарий о невозможности скачать файл. Query и
fragment абсолютных и относительных URL удаляются; `AccountKey`,
`SharedAccessSignature`, `password`, OAuth/API-key/client-secret и отдельный
`Bearer <token>` заменяются на `[REDACTED]`. Полный query удаляется как из
абсолютного, так и из относительного URL; bare `sig=`, `skoid=` и `sktid=`
редактируются и вне URL. Короткие имена SAS-параметров `sp`, `st`, `se`
обрабатываются только как часть URL query, чтобы не портить обычный текст
ошибок ложными совпадениями.

### 4.5. Status Function

Добавлена POST-only Function `ANYRUN-Sandbox-MDE-Status` с `authLevel:
function`. Она делает только короткое чтение JSON по `job_id` и возвращает
`200`, `400`, `404` или `500`. Публичный anonymous endpoint не добавлен.

Отдельная status Function лучше прямого доступа Logic App к Storage: в Logic
App не появляется Storage key/SAS и сохраняется единый контракт состояния.

### 4.6. Logic App

После стартового `202` workflow сохраняет `job_id` и выполняет два `Until`:

1. каждые 15 секунд ждёт отправки evidence в ANY.RUN;
2. каждые 30 секунд ждёт terminal state `completed` или `failed`.

Между ними добавлен Compose **Evidence submitted to ANY.RUN**. В конце добавлен
Compose **ANY.RUN verdict received**. Эти блоки видны в той же Runs history, где
сейчас виден стартовый Function action. Ошибка worker переводит Logic App run в
`Failed`, а не оставляет зелёный запуск с невыполненным анализом.

Первый цикл ограничен одним часом, второй — двумя часами. Сам worker имеет
90-минутный application deadline, поэтому штатная ошибка должна быть записана
до того, как Logic App достигнет собственного лимита.

`DisableAsyncPattern` оставлен только у starter actions. Это правильно: starter
сам возвращает окончательный `202` своего короткого вызова, а дальнейший статус
контролируется нашим явным контрактом, а не несуществующим `Location` header.

### 4.7. ARM и retention

Function ARM template создаёт:

- private container `anyrun-job-status`;
- app setting `AnyRunJobStatusContainerName`;
- семидневное удаление status blobs в существующей optional lifecycle policy.

Новые Defender API permissions не нужны. Новый Storage RBAC role также не
нужен: status использует уже переданный Function App connection string.

Lifecycle policy по-прежнему включается установщиком только для выделенного
Storage Account, созданного этим установщиком. Для reused/shared account она не
перезаписывается, потому что management policy является общей для всего account
и могла бы затронуть чужие правила. В shared account оператор должен настроить
retention самостоятельно, если это требуется политикой организации.

### 4.8. Ветка и артефакты

Все test deployment links, `packageUri` и default `RepositoryRef` направлены на
`refs/heads/asyncv2`. После изменения source ZIP-пакеты пересобираются
детерминированным скриптом, а все шесть SHA-256 в installer обновляются по
фактическим файлам.

Repository `yaestkit/anyrun-integration-microsoft` выбран намеренно: это
тестовый fork для ветки `asyncv2`. В рамках этой сборки он не заменяется на
`anyrun/anyrun-integration-microsoft`. Перед публикацией в другом repository
владелец релиза должен отдельно изменить repository defaults, ссылки,
`packageUri`, тестовые ожидания и повторно вычислить SHA-256.

### 4.9. Исправления, унаследованные от базовой сборки 2026-09-29

Они присутствуют в полной папке, но не являются новым delta `asyncv2`:

- PowerShell URI использует `$($FunctionAppName)?api-version=...`, поэтому `?`
  не интерпретируется как часть имени переменной;
- перед чтением `principalId` выполняются null-safe проверки `site.identity`;
- временный `404 ResourceNotFound` нового Machine Action обрабатывается узким
  read retry в Defender-клиенте.

Файлы `CHANGELOG.md`, `AUDIT-DISPOSITION-2026-09-28.md` и
`AUDIT-RATIONALE-RU-2026-09-28.md` отсутствовали уже в фактической базовой папке
`MDE-full-folder-replacement-2026-09-29`; `asyncv2` их не удаляла. Старые
промежуточные audit artifacts намеренно не восстановлены как runtime-документы.

## 5. Что намеренно не сделано

### Не возвращён синхронный долгий HTTP-вызов

Он снова создал бы исходный timeout и связал бы время выполнения Logic App с
лимитами HTTP action/Function ingress.

### Не использован callback/webhook из worker в Logic App

Callback потребовал бы хранить callback URL с секретной подписью, защищать его,
обрабатывать потерянные callback-и и всё равно иметь reconciliation-механизм.
Периодический short polling здесь проще и надёжнее.

### Не добавлены Durable Functions

Durable orchestration подходит для более сложного fan-out/fan-in, но в данном
случае потребовала бы миграции существующего рабочего queue pipeline и нового
набора operational semantics. Для двух наблюдаемых milestone это избыточно.

### Не включены широкие автоматические повторы worker

Операция запуска ANY.RUN не имеет реализованного идемпотентного ключа. Повтор
после частичного успеха опаснее единичного явного failure. Poison message можно
разобрать и переиграть осознанно.

### Не изменён runtime TI Feeds

Проблема относится к MDE Sandbox. В TI Feeds изменены только ссылки/branch ref,
необходимые для того, чтобы полная папка развертывалась из ветки `asyncv2`.

### Не добавлены секреты в observability

Runs history и status API считаются операторским интерфейсом, но не secret
store. Поэтому там нет полного URL с query parameters, тела sample и
аутентификационных данных.

### Отсутствие отправленного evidence не превращено в успешный результат

`analysis_count: 0` не считается `completed`, потому что основная функция
коннектора — передать evidence и получить verdict. Зелёный run при удалённом
файле или недоступном endpoint создавал бы ложное подтверждение анализа. Поэтому
остаются evidence-specific комментарий, terminal `failed` и poison message для
операционного разбора. Это ожидаемый operational failure, а не успешный skip.

## 6. Ограничения, которые нужно учитывать при ревью

- Polling выполняет примерно четыре status-запроса в минуту до submission и два
  во время анализа. Каждая итерация содержит три Logic App actions (`Wait`,
  `Function`, `SetVariable`), то есть примерно 12 и 6 actions в минуту
  соответственно.
- В classic Logic App UI детали итераций `Until` удобнее раскрывать после их
  завершения; top-level milestone blocks остаются видимыми всегда.
- При использовании существующего shared Storage Account автоматический
  retention выключен; status blobs остаются до ручной политики или удаления.
- Replay poison message после частичной submission остаётся ручной операцией и
  может создать duplicate analysis.
- Если анализ и enrichment Defender завершились, но terminal status не удалось
  сохранить, Logic App не увидит `completed`: она может получить ошибку status
  endpoint либо дождаться двухчасового лимита и завершиться как `Failed`.
  Источником истины в этом редком degraded-сценарии являются комментарий и
  результаты в Defender alert плюс Function logs; такой run нельзя автоматически
  replay-ить, иначе возможна повторная платная задача.
- Status Blob client работает fail-fast: SDK retries отключены, transport
  timeout ограничен, а поверх него действуют application budgets 10/30 секунд.
  Это сознательный компромисс: потеря части progress telemetry безопаснее, чем
  задержка Live Response и ANY.RUN обработки из-за многоуровневых повторов.
- Финальное подтверждение требует end-to-end теста в Azure tenant: ARM/unit
  tests не эмулируют Live Response, Logic App billing и задержки ANY.RUN API.

## 7. Что проверить в тестовом tenant

1. Развернуть полную папку из ветки `asyncv2` новым installer run.
2. Убедиться, что в Function App появились три Functions: starter, worker и
   status.
3. Убедиться, что container `anyrun-job-status` имеет Private access.
4. Запустить Windows EDR/AV alert с доступным файлом.
5. Проверить, что starter возвращает `202` за несколько секунд.
6. В Logic App Runs history проверить блок **Evidence submitted to ANY.RUN** и
   наличие task UUID/link.
7. Дождаться **ANY.RUN verdict received** и сверить verdict с ANY.RUN task и
   комментарием Defender.
8. Проверить alert с двумя evidence: в `analyses` должны сохраниться оба
   результата.
9. Выполнить отрицательный тест с недоступным evidence/API и убедиться, что run
   завершается `Failed`, status содержит короткую ошибку, а сообщение находится
   в poison queue.
10. Повторно запустить installer и проверить идемпотентность deployment.

## 8. Критерии принятия

- Ни один долгий Live Response/ANY.RUN этап не выполняется внутри HTTP action.
- Logic App не становится `Succeeded` только из-за получения `202`.
- Submission и terminal verdict видны в Runs history.
- Ошибка worker видна и в Logic App, и в технических логах.
- В status JSON нет секретов и sample content.
- Package ZIP совпадает с checked-in source, а installer SHA-256 совпадают со
  всеми шестью артефактами.
- Все локальные unit/contract tests проходят.

## 9. Локальная проверка этой папки

В финальной сборке выполнено:

- Sandbox: 58 тестов;
- TI Feeds: 25 тестов;
- installer и общие deployment contracts: 29 тестов;
- всего: 112 успешно пройденных тестов;
- JSON-проверка ARM, Logic App, Function bindings и `host.json`;
- Python syntax compilation исходников Sandbox и TI Feeds;
- детерминированная пересборка обоих Function ZIP;
- проверка, что содержимое ZIP побайтно соответствует checked-in source;
- проверка всех шести SHA-256, встроенных в installer.

Это локальная проверка контракта и артефактов. Azure ARM validation и полный
end-to-end запуск должны быть выполнены после публикации ветки `asyncv2`, потому
что `packageUri` и Deploy-to-Azure links специально ссылаются на эту ветку.

## 10. Решения по замечаниям аудита 2026-09-30

| Замечание | Решение | Обоснование |
|---|---|---|
| Blob status мог прервать уже запущенный анализ | Исправлено | Progress writes стали best-effort с bounded retry; они больше не выбрасывают исключение в business pipeline. |
| `worker_started` и `completed` находились вне `try` | Исправлено | Инициализация включена в общий error path. Terminal writes имеют пять попыток; сбой `completed` не создаёт poison/replay risk. |
| Ошибка могла содержать SAS/token | Исправлено | URL query/fragment и чувствительные assignments редактируются до status, Logic App runError, Defender comment и worker error message. |
| Evidence-specific Defender comment мог получить SAS из `requests` exception | Исправлено | Sanitizer вынесен в общий модуль и применяется в `processor.py`, на границе Defender client и во всех внешних error channels. |
| Sanitizer пропускал `AccountKey`, connection string и отдельный `Bearer` | Исправлено | Добавлены `AccountKey`, `SharedAccessSignature`, `password`, standalone Bearer и relative-query cases; короткие `sp/st/se` больше не маскируют обычный текст. |
| Blob SDK retries могли умножаться на повторы worker | Исправлено | Status client использует zero SDK retries, connect/read timeout 3/5 секунд и общие application budgets 10/30 секунд. |
| Отключение SDK retries оставило starter без защиты от transient Storage error | Исправлено | Starter повторяет одну и ту же idempotent pre-enqueue запись до трёх раз; queue message создаётся только после успеха. |
| Bare `sig=` мог пройти вне URL query | Исправлено | `sig`, `skoid` и `sktid` маскируются как standalone assignments; `sp/st/se` намеренно остаются query-only. |
| При потере `completed` Logic App может показать `Failed` после успешного анализа | Документировано | Worker намеренно не создаёт poison message и оставляет tracking-warning в Defender; раздел 6 описывает расхождение и запрещает автоматический replay. |
| `permanentUrl` мог содержать query | Исправлено | Task URL дополнительно нормализуется перед записью в status. |
| Нет тестов негативных status paths | Исправлено | Добавлены starter 500/no enqueue, empty analyses, Status 400/404/500, initial/intermediate/final Blob failures и redaction. |
| ARM description говорил только про один день | Исправлено | Теперь явно указаны evidence 1 day и status 7 days; это защищено тестом. |
| Стоимость polling описана как число actions | Исправлено | Раздел 6 различает status requests и три Logic App actions на итерацию. |
| `MAX_DEQUEUE_COUNT` дублировал `host.json` | Исправлено | Константа удалена; источник настройки queue retry только `host.json`. |
| Смена repository не описана | Документировано, код не изменён | `yaestkit` — намеренный test fork по условиям этой сборки. |
| `analysis_count: 0` предложено считать успехом | Не принято | Успех без submission/verdict вводит оператора в заблуждение; это operational failure. |
| Вернуть старые audit/changelog files | Не принято | Эти файлы отсутствуют в фактической полной базе 2026-09-29 и не удалялись `asyncv2`. |
| PowerShell interpolation/null checks и MDE 404 retry не описаны | Документировано | Это полезные, но унаследованные изменения базовой сборки, а не новый delta `asyncv2`. |

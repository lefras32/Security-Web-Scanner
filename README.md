# Security Web Scanner

Небольшой API на FastAPI для проверки HTTP-заголовков безопасности публичных веб-сайтов.

## Возможности

- Проверяет `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` и `Permissions-Policy`.
- Возвращает найденные и отсутствующие заголовки, рекомендации и оценку от 0 до 100.
- Разрешает только HTTP/HTTPS и порты 80/443.
- Блокирует непубличные IP-адреса, включая адреса из DNS-ответов, и проверяет каждый редирект (не более пяти).
- Читает заголовки ответа, не загружая тело целиком.

Оценка показывает только наличие заголовков, а не корректность их директив и не является полноценным аудитом безопасности. `Strict-Transport-Security` учитывается только для HTTPS-ответа.

## Требования

- Python 3.10 или новее

## Установка и запуск

Из корня проекта выполните:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

Интерактивная документация API: <http://127.0.0.1:8000/docs>.

## Использование

Отправьте `POST /scan` с URL сайта:

```powershell
$body = @{ url = "https://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/scan" -Method Post -ContentType "application/json" -Body $body
```

Ответ содержит `target_url`, `security_score`, `headers_found`, `headers_missing` и `recommendations`.

Основные статусы ответа: `200` — сканирование выполнено; `400` — URL запрещён или не поддерживается; `422` — некорректный запрос; `502` — ошибка подключения или ответа целевого сервера; `504` — истёк таймаут.

## Тесты

```powershell
python -m unittest discover -s tests -v
```

## Безопасное использование

Сканируйте только сайты, на проверку которых у вас есть разрешение. Сервис намеренно блокирует localhost, частные и другие непубличные адреса, а также порты, отличные от 80 и 443.
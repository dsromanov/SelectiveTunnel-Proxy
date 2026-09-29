# Версия 2.0.0 — нативный C++ клиент

- PowerShell GUI/служба заменены на `SelectiveTunnel.exe` + Windows Service `SelectiveTunnelSvc`.
- Сохранена схема 1.1.0: sing-box stdin, DPAPI, NRPT только своих доменов, FakeIP TUN, kill-switch, аддитивный импорт правил.
- Сосуществование с Happ: DNS `127.0.0.53`, FakeIP `100.82.0.0/16` вместо `198.18.0.0/15`, bind исходящих на физический NIC, установка не падает из‑за чужого NRPT.
- Telegram в политику не добавляется.
- IPv4-only TUN по умолчанию. Миграция с 1.1.0 через Update.cmd снимает legacy-маршруты 198.18/15.
- Эталон PowerShell остаётся в `legacy/client`.

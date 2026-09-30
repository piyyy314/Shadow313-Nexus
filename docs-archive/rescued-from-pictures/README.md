# Fortress_Command Suite

## Features
- **Modular defense & attack orchestration**
- Centralized config, logging & alerting
- Live CLI dashboard (`fortress_monitor.py`)
- Automated updates, health checks, and SIEM/Elastic/Telegram/Discord integration
- Active defense & threat intel expansion

## Setup
1. Copy example `fortress_config.py`, update your keys, ports, etc.
2. `pip install -r requirements.txt`
3. Run each module directly or with `python fortress_main.py`
4. View live logs: `python fortress_monitor.py`

## Docker
Build with:
```
docker-compose build
docker-compose up
```
## API
Provides `/status`, `/logs`, and `/start_module` endpoints.

**See individual scripts for details and expansion.**
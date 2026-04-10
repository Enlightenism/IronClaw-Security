# IronClaw Gen1

IronClaw Gen1 is a local-first FastAPI API for scanning targets, returning a verdict, and storing scan history with stable scan IDs.

## Features

- Create scans with `POST /scan/`
- View recent scans with `GET /history/`
- Fetch a single saved scan with `GET /history/{scan_id}`
- Check service status with `GET /health`
- Persist local scan history
- Run locally with Docker Compose health monitoring

## Local setup

```powershell
py -m pip install -r requirements.txt
```

## Run with Docker Compose

```powershell
docker compose up -d --build
docker compose ps
```

Then open:

- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/health

## Stop

```powershell
docker compose down
```

## Test

```powershell
py -m pytest -q
```

## Example scan

```json
{
  "target_type": "url",
  "target_value": "https://example.com"
}
```

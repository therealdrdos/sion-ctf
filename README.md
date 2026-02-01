# SION-CTF

AI-powered CTF learning platform. Generate vulnerable web applications on-demand, get tailored tutorials, and learn to hack.

## Tech Stack

- **Backend**: Python 3.14, FastAPI 0.128
- **Frontend**: HTMX 2.0, TailwindCSS 4.1
- **Database**: SQLite3
- **Container Management**: Docker SDK 7.1
- **AI**: OpenAI API (gpt-4o)

## Features

- Chat interface for CTF challenge generation
- Multiple vulnerability types: SQL Injection, XSS, Command Injection, Path Traversal, IDOR, Broken Auth
- Difficulty levels: Easy, Medium, Hard
- Auto-generated tutorials with progressive hints
- Docker container deployment for challenges
- Challenge validation before delivery

## How to Run

### Prerequisites

- Python 3.12+
- Docker (running)
- OpenAI API key

### Local Development

```bash
# Clone the repo
git clone https://github.com/your-team/sion-ctf.git
cd sion-ctf

# Install dependencies
pip install uv
uv sync --all-extras

# Set up environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Run the server
uv run uvicorn app.main:app --reload
```

Open http://localhost:8000

### Background jobs (Celery)

- Requires Redis (`REDIS_URL`, default `redis://localhost:6379/0`)
- Start worker:
  ```bash
  celery -A app.celery_app.celery_app worker --loglevel=info
  ```
- API endpoints:
  - `POST /api/jobs` with JSON `{ "prompt": "...", "difficulty": "easy|medium|hard", "vuln_type": "sqli|cmdi|path|auth|idor|xss" }` → returns `job_id`
  - `GET /api/jobs/{job_id}/status` → `{status, progress, message, logs, result}`

### Docker Deployment

```bash
# Build and run
docker compose up --build

# Or manually
docker build -t sion-ctf .
docker run -p 8000:8000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e OPENAI_API_KEY=your-key \
    -e SECRET_KEY=your-secret \
    sion-ctf
```

### Production Deployment with Challenge Proxy

For production, challenges are accessed via a subdomain through a reverse proxy.
This is required when firewalls block direct access to dynamic Docker ports.

**Architecture:**
- Main app: `sion-ctf.pro` (port 8000)
- Challenge proxy: `challenge.sion-ctf.pro` (port 5000)
- Challenges: `challenge.sion-ctf.pro/{challenge_id}/`

**Setup:**

1. Set the challenge proxy URL in your environment:
   ```bash
   export CHALLENGE_PROXY_URL=https://challenge.sion-ctf.pro
   ```

2. Run the challenge proxy:
   ```bash
   # Option A: Direct (recommended for VM deployment)
   uv run uvicorn app.challenge_proxy:app --host 127.0.0.1 --port 5000

   # Option B: Systemd service
   sudo cp sion-ctf-proxy.service /etc/systemd/system/
   sudo systemctl enable --now sion-ctf-proxy

   # Option C: Docker Compose
   docker compose up -d challenge-proxy
   ```

3. Configure your reverse proxy (nginx example):
   ```nginx
   server {
       server_name challenge.sion-ctf.pro;
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

## Usage

1. Register an account
2. Select difficulty and vulnerability types
3. Describe the vulnerable app you want
4. Wait for generation and deployment
5. Click "Open Challenge" to start hacking
6. Use the tutorial for hints when stuck

## Security Notes

- CTF containers run in an isolated Docker network
- Resource limits: 512MB RAM, 0.5 CPU per container
- Containers auto-cleanup on app shutdown
- Rate limiting: 30s between challenge generations

## Project Structure

```
app/
  main.py            # Main FastAPI app (port 8000)
  challenge_proxy.py # Challenge proxy (port 5000)
  config.py          # Settings
  db.py              # SQLite
  auth/              # Authentication
  ctf/               # CTF generation, validation, Docker
  tutorial/          # Tutorial generation
  templates/         # Jinja2 HTML
tests/               # pytest tests
sion-ctf-proxy.service  # Systemd service for proxy
```

## License

MIT

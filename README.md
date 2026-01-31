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
  main.py          # FastAPI app
  config.py        # Settings
  db.py            # SQLite
  auth/            # Authentication
  ctf/             # CTF generation, validation, Docker
  tutorial/        # Tutorial generation
  templates/       # Jinja2 HTML
tests/             # pytest tests
```

## License

MIT

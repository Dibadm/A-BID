# Koyeb Deploy (No Credit Card Required)

## 1. Create Free Databases (External, No CC)

### Neon Postgres (Free Tier)
1. Go to https://neon.tech → Sign up with GitHub
2. Create project → Copy connection string
3. Format: `postgresql://user:pass@ep-xxx.us-east-1.aws.neon.tech/neondb?sslmode=require`

### Upstash Redis (Free Tier)
1. Go to https://upstash.com → Sign up with GitHub
2. Create database → Copy connection string
3. Format: `rediss://:password@host:port`

## 2. Deploy to Koyeb (Web UI)

1. Go to https://app.koyeb.com → Sign up with GitHub
2. Click **"Create App"** → **"GitHub"**
3. Select repo: `Dibadm/A-BID`
4. **Builder**: Dockerfile
5. **Instance**: Free (512MB RAM, 0.1 vCPU)
6. **Port**: 8080 (HTTP + WebSocket)
7. **Environment Variables**:
   ```
   DATABASE_URL=<neon-connection-string>
   REDIS_URL=<upstash-connection-string>
   JWT_SECRET=<run: openssl rand -hex 32>
   DEV_MODE=0
   ```
8. **Commands** (in Dockerfile, already set):
   - `python seed.py && uvicorn main:app --host 0.0.0.0 --port 8080`

9. **Add Second Service** for timer loop:
   - Click "Add Service" → "Worker"
   - Same repo, same Dockerfile
   - **Command override**: `python -c "import asyncio, main; asyncio.run(main.timer_loop())"`
   - No port needed

10. Deploy!

## 3. Result
- App: `https://lowbid-ethiopia-<org>.koyeb.app`
- WebSocket: `wss://lowbid-ethiopia-<org>.koyeb.app/ws`
- Free forever, no sleep, no CC
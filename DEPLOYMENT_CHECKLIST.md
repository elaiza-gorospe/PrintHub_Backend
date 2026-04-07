# Render.com Deployment Checklist

## Pre-Deployment ✅

- [ ] All code committed and pushed to GitHub
- [ ] `.env` file is in `.gitignore` (never commit secrets)
- [ ] Verify `render.yaml` exists in project root
- [ ] Test locally: `npm start` works correctly
- [ ] Verify Prisma migrations are in `prisma/migrations/`

## Render Setup

- [ ] Create account at [render.com](https://render.com)
- [ ] Have Neon database ready
  - [ ] Get connection string from [Neon Console](https://console.neon.tech)
  - [ ] Connection string starts with `postgresql://`
- [ ] Create Web Service
  - [ ] Connect GitHub repo
  - [ ] Set build command: `npm install && npx prisma generate && npx prisma migrate deploy`
  - [ ] Set start command: `npm start`

## Environment Variables (in Render Dashboard)

- [ ] `DATABASE_URL` → (Paste connection string from Neon)
- [ ] `NODE_ENV` → `production`
- [ ] `EMAIL_USER` → your gmail
- [ ] `EMAIL_PASS` → app-specific password (not your regular password)
- [ ] `PORT` → `3000`

## Deployment

- [ ] Push final code to GitHub
- [ ] Monitor deployment in Render dashboard
- [ ] Check deployment logs for errors
- [ ] Verify API is accessible at `https://printhub-api.onrender.com`

## Post-Deployment

- [ ] Test API endpoints
- [ ] Update frontend API_URL to point to new server
- [ ] Verify email OTP functionality works
- [ ] Test database operations (create, read, update)
- [ ] Set up monitoring/alerts in Render

## Quick Links

- Render Dashboard: https://dashboard.render.com
- Neon Console: https://console.neon.tech
- Your API (after deploy): https://printhub-api.onrender.com
- Prisma Docs: https://www.prisma.io/docs/

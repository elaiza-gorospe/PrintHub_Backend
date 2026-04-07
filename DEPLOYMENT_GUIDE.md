# PrintHub Backend - Deployment Guide for Render.com

## Prerequisites

- GitHub repository with your code committed
- Render.com account
- PostgreSQL database (Render provides managed PostgreSQL)

## Step 1: Prepare Your Repository

1. Make sure all files are committed to git:

   ```
   git add .
   git commit -m "Prepare for Render deployment"
   git push origin main
   ```

2. Ensure `.gitignore` includes:
   - `node_modules/`
   - `.env`
   - `.env.*`

## Step 2: Get Database Connection String from Neon

1. Go to [Neon Console](https://console.neon.tech)
2. Select your project/database
3. Click "Connection string" or "Connection details"
4. Copy the connection string that starts with `postgresql://`
5. Keep this handy for the next step

## Step 3: Deploy API on Render

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `printhub-api`
   - **Environment**: `Node`
   - **Build Command**: `npm install && npx prisma generate && npx prisma migrate deploy`
   - **Start Command**: `npm start`
   - **Plan**: Free (can upgrade later)

## Step 4: Set Environment Variables

In the Render dashboard for your web service, add these environment variables:

```
DATABASE_URL=<paste the connection string from Neon>
NODE_ENV=production
PORT=3000
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=your-app-specific-password
```

**For DATABASE_URL**: Paste the full Neon connection string (usually looks like: `postgresql://user:password@neon-host.com/dbname?sslmode=require`)

**For Gmail Email (EMAIL_USER & EMAIL_PASS)**:

1. Enable 2-Factor Authentication on your Google Account
2. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
3. Select "Mail" and "Windows Computer"
4. Copy the generated 16-character password
5. Use this as `EMAIL_PASS`

## Step 5: Deploy

1. Render will automatically deploy when you push to your main branch
2. Watch the deployment logs in the Render dashboard
3. Once deployed, your API will be available at: `https://printhub-api.onrender.com`

## Troubleshooting

correct Neon connection string from the Neon console

- Verify the connection string includes `?sslmode=require` at the end
- Check Neon dashboard to confirm the database is running
- Test the connection locally by setting DATABASE_URL and running: `npx prisma db push`
- Ensure `DATABASE_URL` is the **Internal Database URL** (not External)
- Check that the web service and database are in the **same region**

### Migration Failures

- Check the deployment logs for specific errors
- Verify your `prisma/migrations` folder is committed to git

### Application Not Starting

- Check logs for missing dependencies
- Verify all environment variables are set correctly
- Ensure `server.js` is executable

## Update Frontend API URL

After deployment, update your frontend to use the new API URL:

```javascript
// In your React app (PrintHub_FrontEnd)
const API_URL = "https://printhub-api.onrender.com";
```

## Useful Commands After Deployment

To view logs:

```
tail -f logs from Render dashboard
```

To manually run migrations:

- Use Render's "Shell" feature to run: `npx prisma migrate deploy`

## Important Notes

- **Free tier**: Free on Render comes with limitations (may sleep after 15 minutes of inactivity)
- **Upgrade when ready**: Move to Paid plan for production use
- **Backups**: Set up automated backups for your PostgreSQL database
- **Monitoring**: Enable alerts in Render dashboard

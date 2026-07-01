# 🔐 GitHub Secrets Setup Guide

This guide walks you through setting up all required GitHub secrets for CI/CD deployments.

## ⚡ Quick Setup (5 minutes)

### Step 1: Go to Repository Settings
1. Open https://github.com/Saraki99/phishing-detector-api
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**

### Step 2: Add Vercel Secrets (Frontend Deployment)

#### Secret 1: `VERCEL_TOKEN`
```
Location: Settings → Secrets and variables → Actions
Name: VERCEL_TOKEN
```

**How to get it:**
1. Go to https://vercel.com/account/tokens
2. Create a new token (select "Full Access" scope)
3. Copy the token
4. Paste in GitHub secret

#### Secret 2: `VERCEL_ORG_ID`
```
Location: Settings → Secrets and variables → Actions
Name: VERCEL_ORG_ID
```

**How to get it:**
1. Go to https://vercel.com/account/settings
2. Look for "Organization ID" or "Team ID"
3. Copy the ID
4. Paste in GitHub secret

#### Secret 3: `VERCEL_PROJECT_ID`
```
Location: Settings → Secrets and variables → Actions
Name: VERCEL_PROJECT_ID
```

**How to get it:**
1. Go to https://vercel.com
2. Create a new project or use existing
3. Project → Settings → "Project ID"
4. Copy the ID
5. Paste in GitHub secret

### Step 3: Add Render Secrets (Backend Deployment)

#### Secret 4: `RENDER_API_KEY`
```
Location: Settings → Secrets and variables → Actions
Name: RENDER_API_KEY
```

**How to get it:**
1. Go to https://dashboard.render.com/account/api-tokens
2. Create a new API token
3. Copy the token
4. Paste in GitHub secret

#### Secret 5: `RENDER_SERVICE_ID`
```
Location: Settings → Secrets and variables → Actions
Name: RENDER_SERVICE_ID
```

**How to get it:**
1. Deploy to Render first (see Render setup)
2. Go to https://dashboard.render.com/services
3. Click your service
4. Copy the service ID from URL or settings
5. Paste in GitHub secret

#### Secret 6: `RENDER_DEPLOY_HOOK`
```
Location: Settings → Secrets and variables → Actions
Name: RENDER_DEPLOY_HOOK
```

**How to get it:**
1. Go to https://dashboard.render.com/services
2. Click your service → Settings
3. Look for "Deploy Hook"
4. Copy the URL
5. Paste in GitHub secret

### Step 4: Add Environment Variables (Optional but Recommended)

#### Secret 7: `NEXT_PUBLIC_API_URL`
```
Location: Settings → Secrets and variables → Actions
Name: NEXT_PUBLIC_API_URL
Value: https://phishguard-api.render.com
```

This is the backend API URL for the frontend to connect to.

#### Secret 8: `API_SECRET_KEY`
```
Location: Settings → Secrets and variables → Actions
Name: API_SECRET_KEY
Value: your-secure-random-key
```

**Generate a secure key:**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Step 5: Add Docker Secrets (Optional)

#### Secret 9: `DOCKER_USERNAME`
```
Location: Settings → Secrets and variables → Actions
Name: DOCKER_USERNAME
Value: your-dockerhub-username
```

#### Secret 10: `DOCKER_PASSWORD`
```
Location: Settings → Secrets and variables → Actions
Name: DOCKER_PASSWORD
Value: your-dockerhub-token
```

**How to get Docker credentials:**
1. Go to https://hub.docker.com/settings/security
2. Create an access token
3. Use your username and this token

---

## 📋 Complete Secrets Checklist

After adding all secrets, you should have:

```
✅ VERCEL_TOKEN
✅ VERCEL_ORG_ID
✅ VERCEL_PROJECT_ID
✅ RENDER_API_KEY
✅ RENDER_SERVICE_ID
✅ RENDER_DEPLOY_HOOK
✅ NEXT_PUBLIC_API_URL
✅ API_SECRET_KEY
✅ DOCKER_USERNAME (optional)
✅ DOCKER_PASSWORD (optional)
```

### Verify Secrets Added
1. Go to Settings → Secrets and variables → Actions
2. You should see at least 6 secrets listed
3. Click "Refresh" if you don't see newly added secrets

---

## 🔒 Security Best Practices

### ✅ DO:
- [ ] Use strong, randomly generated tokens
- [ ] Rotate tokens every 90 days
- [ ] Use least privilege access
- [ ] Never commit secrets to git
- [ ] Use environment-specific tokens
- [ ] Monitor secret usage in logs

### ❌ DON'T:
- [ ] Share secrets via email or chat
- [ ] Commit secrets to repository
- [ ] Use personal tokens
- [ ] Reuse tokens across services
- [ ] Share development tokens
- [ ] Log secret values

---

## 🐛 Troubleshooting

### Secret not found in workflow
```
Error: Unable to locate secret
```
**Solution:**
- Verify secret name matches exactly (case-sensitive)
- Check secret is in correct repository (not organization)
- Wait 5 minutes after adding secret
- Refresh the page and try again

### Deployment fails with authentication error
```
Error: Authentication failed
```
**Solution:**
- Verify token is not expired
- Check token has correct permissions
- Regenerate token and update secret
- Verify organization access

### Secret shows as "undefined"
```
Error: Secret value is undefined
```
**Solution:**
- Check secret name in workflow YAML
- Verify secret exists in Settings
- Ensure secret is not empty
- Re-add secret if corrupted

---

## 🔄 Rotating Secrets

Every 90 days, rotate your secrets:

1. **Vercel Token:**
   - Go to https://vercel.com/account/tokens
   - Delete old token
   - Create new token
   - Update GitHub secret

2. **Render API Key:**
   - Go to https://dashboard.render.com/account/api-tokens
   - Delete old token
   - Create new token
   - Update GitHub secret

3. **Docker Token:**
   - Go to https://hub.docker.com/settings/security
   - Delete old token
   - Create new token
   - Update GitHub secret

---

## 📊 Secrets Verification Table

| Secret Name | Service | Required | Type |
|---|---|---|---|
| VERCEL_TOKEN | Vercel | ✅ Yes | API Token |
| VERCEL_ORG_ID | Vercel | ✅ Yes | ID |
| VERCEL_PROJECT_ID | Vercel | ✅ Yes | ID |
| RENDER_API_KEY | Render | ✅ Yes | API Key |
| RENDER_SERVICE_ID | Render | ✅ Yes | ID |
| RENDER_DEPLOY_HOOK | Render | ✅ Yes | URL |
| NEXT_PUBLIC_API_URL | Frontend Config | ⚠️ Optional | URL |
| API_SECRET_KEY | Backend Config | ⚠️ Optional | Key |
| DOCKER_USERNAME | Docker | ❌ No | Username |
| DOCKER_PASSWORD | Docker | ❌ No | Token |

---

## ✨ Next Steps

After adding all secrets:

1. ✅ Push code to `phishguard-enterprise` branch
2. ✅ GitHub Actions will automatically trigger
3. ✅ Monitor deployment in Actions tab
4. ✅ Frontend will deploy to Vercel
5. ✅ Backend will deploy to Render
6. ✅ Check URLs for live deployment

---

## 📞 Support

**Need help?**
- Check GitHub Actions logs: Settings → Actions
- Verify secret values are correct
- Review deployment logs in Vercel/Render
- Check browser console for errors

**Links:**
- [GitHub Secrets Docs](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Vercel Documentation](https://vercel.com/docs)
- [Render Documentation](https://render.com/docs)

---

*Setup Time: ~5 minutes*
*Status: Ready for deployment*

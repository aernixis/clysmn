# clysmn

## Deploy to Render via GitHub

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Web Service → connect your repo
3. Render will auto-detect `render.yaml` and set everything up
4. **Add one environment variable** in Render dashboard:
   - `TOKEN_SECRET` → any long random string (e.g. generate at https://randomkeygen.com)
   - Or leave it — `render.yaml` will auto-generate one

## Google OAuth Setup

In [Google Cloud Console](https://console.cloud.google.com):
1. Go to APIs & Services → Credentials → your OAuth client
2. Add your Render URL to **Authorized JavaScript origins**
   - e.g. `https://clysmn.onrender.com`
3. Save

## Testing shortcuts (on the sign-in screen only)

- Press **X** → bypass auth, go straight into the app
- Press **Z** → simulate an unauthorized user (shows denied screen + redirects)

## How auth works

- First visit: Google sign-in popup appears
- Server verifies the Google credential and checks the whitelist
- If authorized: a signed token is stored in `localStorage` **permanently**
- Future visits: token is verified silently, no popup ever again
- Owners (`aernatas@gmail.com`, `fhuang@princetonk12.org`) can manage the whitelist in Settings

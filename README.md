# HouseDepot
Flask + MySQL + Gmail OTP. DB name: housedepot

## Quick start
1) Install deps: `python -m pip install -r requirements.txt`
2) Create DB/tables: open MySQL and run `schema.sql`
3) Copy `.env.example` to `.env` (already included with your values)
4) Run: `python app.py` (or `python -m flask run`)

Admin (seeded on first run):


If OTP mail fails, the server will log a fallback line starting with `[DEV OTP EMAIL FAILED]`.

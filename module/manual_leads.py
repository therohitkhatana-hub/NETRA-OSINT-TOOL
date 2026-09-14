"""
Manual investigation leads for NETRA.
Provides actionable investigator tips and search URL constructions without ToS-violating scraping.
"""
from urllib.parse import quote
from db import Finding


def phone_manual_leads(phone: str) -> list[Finding]:
    digits = "".join(ch for ch in phone if ch.isdigit())
    q = quote(phone)

    leads = [
        ("WhatsApp click-to-chat (manual)", f"https://wa.me/{digits}",
         "opens a chat with this number if it has WhatsApp — profile photo/status/last-seen visible if the target's privacy settings allow it; this is WhatsApp's own intended link mechanism, not a scrape"),
        ("Telegram (manual)", "https://web.telegram.org",
         "Telegram has no direct phone-number deep link — add the number as a contact manually to check for a linked account"),
        ("Truecaller (manual, requires their app/site)", "https://www.truecaller.com",
         "caller-ID lookup — free tier requires signing in and submitting your own contact list to their database as part of using the service; a real trade-off to be aware of, not something this tool automates"),
        ("Area/country code reference", "https://en.wikipedia.org/wiki/List_of_mobile_phone_number_series",
         "manual cross-check against phonenumbers library's own region/carrier output above"),
        ("Google dork", f"https://www.google.com/search?q=%22{q}%22",
         "exact-match search across the open web"),
        ("Bing search", f"https://www.bing.com/search?q=%22{q}%22", "often surfaces different results than Google"),
        ("Yandex search", f"https://yandex.com/search/?text=%22{q}%22", "stronger coverage of Eastern European/Russian-language sources"),
        ("Google filetype dork (documents)", f"https://www.google.com/search?q=%22{q}%22+filetype:pdf+OR+filetype:doc+OR+filetype:xls",
         "finds the number leaked in resumes, forms, or reports indexed by Google"),
        ("PublicWWW source-code search", f"https://publicwww.com/websites/%22{q}%22/",
         "finds the number embedded in website source/HTML — free tier caps result count"),
    ]
    return [
        Finding(phone, "manual_leads", f"LEAD (manual step required): {name} — {url} ({note})", 0.2, url)
        for name, url, note in leads
    ]


def email_manual_leads(email: str) -> list[Finding]:
    q = quote(email)

    leads = [
        ("Google dork", f"https://www.google.com/search?q=%22{q}%22", "exact-match search across the open web"),
        ("Bing search", f"https://www.bing.com/search?q=%22{q}%22", "often surfaces different results than Google"),
        ("Yandex search", f"https://yandex.com/search/?text=%22{q}%22", "stronger coverage of Eastern European/Russian-language sources"),
        ("Google filetype dork (documents)", f"https://www.google.com/search?q=%22{q}%22+filetype:pdf+OR+filetype:doc+OR+filetype:xls",
         "finds the address leaked in resumes, forms, or reports indexed by Google"),
        ("PublicWWW source-code search", f"https://publicwww.com/websites/%22{q}%22/",
         "finds the address embedded in website source/HTML — free tier caps result count"),
        ("LinkedIn search (manual)", f"https://www.linkedin.com/search/results/all/?keywords={q}",
         "LinkedIn's own search box, run against the email string — not every account is discoverable this way, depends on the user's search-visibility settings"),
    ]
    return [
        Finding(email, "manual_leads", f"LEAD (manual step required): {name} — {url} ({note})", 0.2, url)
        for name, url, note in leads
    ]

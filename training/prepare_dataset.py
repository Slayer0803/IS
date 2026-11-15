"""
Dataset Preparation & Domain-Aware Partitioning Script.
Prepares structured phishing and legitimate datasets with strict domain-aware / campaign-aware splitting
to simulate realistic zero-day phishing detection without target domain leakage.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


# Benchmark dataset containing verified legitimate domains and realistic phishing campaigns
# Grouped by campaign to enforce campaign-level zero-day splits.
BENCHMARK_SAMPLES = [
    # --- LEGITIMATE SAMPLES (Train Domains: google.com, github.com, wikipedia.org, etc.) ---
    {
        "url": "https://www.google.com/search?q=machine+learning",
        "domain": "google.com",
        "campaign_id": "legit_search",
        "text": "Google Search machine learning algorithms artificial intelligence news documentation",
        "html": "<html><head><title>Google Search</title></head><body><h1>Google</h1><input type='text' name='q'><button>Search</button></body></html>",
        "label": 0
    },
    {
        "url": "https://github.com/torvalds/linux",
        "domain": "github.com",
        "campaign_id": "legit_dev",
        "text": "GitHub Linux source tree repositories code issues pull requests documentation open source",
        "html": "<html><head><title>Linux Kernel Source - GitHub</title></head><body><h1>torvalds/linux</h1><p>Linux kernel source tree</p><a href='/issues'>Issues</a></body></html>",
        "label": 0
    },
    {
        "url": "https://en.wikipedia.org/wiki/Phishing",
        "domain": "wikipedia.org",
        "campaign_id": "legit_edu",
        "text": "Wikipedia Phishing is the fraudulent attempt to obtain sensitive information like usernames passwords",
        "html": "<html><head><title>Phishing - Wikipedia</title></head><body><h1>Phishing</h1><p>Phishing attacks typically utilize social engineering</p></body></html>",
        "label": 0
    },
    {
        "url": "https://stackoverflow.com/questions/tagged/python",
        "domain": "stackoverflow.com",
        "campaign_id": "legit_dev",
        "text": "Stack Overflow where developers learn share their programming knowledge and build their careers",
        "html": "<html><head><title>Newest Python Questions - Stack Overflow</title></head><body><h1>Questions</h1><p>Find answers to your programming problems</p></body></html>",
        "label": 0
    },
    {
        "url": "https://docs.python.org/3/library/index.html",
        "domain": "python.org",
        "campaign_id": "legit_docs",
        "text": "The Python Standard Library documentation built-in functions data types numeric mathematical modules",
        "html": "<html><head><title>The Python Standard Library</title></head><body><h1>Library Documentation</h1><p>Reference manuals</p></body></html>",
        "label": 0
    },
    {
        "url": "https://news.ycombinator.com/",
        "domain": "ycombinator.com",
        "campaign_id": "legit_news",
        "text": "Hacker News top stories new past comments ask show jobs submit technology startup news",
        "html": "<html><head><title>Hacker News</title></head><body><h1>Hacker News</h1><table><tr><td><a href='https://news.com'>Story 1</a></td></tr></table></body></html>",
        "label": 0
    },

    # --- KNOWN PHISHING CAMPAIGNS (Assigned to Training Set) ---
    {
        "url": "http://paypal-verification-alert.com/signin",
        "domain": "paypal-verification-alert.com",
        "campaign_id": "paypal_known_wave_1",
        "text": "PayPal Log In to your account. Urgent: Your account has been temporarily locked due to suspicious activity.",
        "html": "<html><head><title>PayPal Login</title></head><body><h2>PayPal</h2><form action='http://paypal-verification-alert.com/post' method='post'><input type='password' name='pw'><button>Log In</button></form></body></html>",
        "label": 1
    },
    {
        "url": "http://update-paypal-security99.com/confirm",
        "domain": "update-paypal-security99.com",
        "campaign_id": "paypal_known_wave_1",
        "text": "PayPal Security Center: Confirm your identity within 24 hours to prevent account suspension.",
        "html": "<html><head><title>PayPal Verification</title></head><body><h2>PayPal</h2><p>Confirm identity</p><form action='http://update-paypal-security99.com/save' method='post'><input type='text' name='email'><input type='password' name='pass'></form></body></html>",
        "label": 1
    },
    {
        "url": "http://microsoft-office-verify.net/auth",
        "domain": "microsoft-office-verify.net",
        "campaign_id": "ms_known_wave_1",
        "text": "Microsoft Sign In. Enter password to keep your session alive. Password required.",
        "html": "<html><head><title>Microsoft Sign In</title></head><body><h1>Microsoft</h1><form action='http://microsoft-office-verify.net/submit'><input type='password' name='p'></form></body></html>",
        "label": 1
    },
    {
        "url": "http://portal-login-microsoft365.info/login",
        "domain": "portal-login-microsoft365.info",
        "campaign_id": "ms_known_wave_1",
        "text": "Microsoft 365 Outlook Web App Sign In with your organizational account immediately.",
        "html": "<html><head><title>Sign in to your account</title></head><body><h1>Sign in</h1><form action='http://portal-login-microsoft365.info/steal.php'><input type='password'></form></body></html>",
        "label": 1
    },

    # --- ZERO-DAY UNSEEN DOMAINS & CAMPAIGNS (Strictly Reserved for Zero-Day Testing) ---
    # These domains have completely different naming schemas, zero overlap with training domains,
    # and mimic novel attack infrastructure.
    {
        "url": "http://x-auth-9941.xyz/token-verify?sid=8831",
        "domain": "x-auth-9941.xyz",
        "campaign_id": "zero_day_cloud_impersonation",
        "text": "Microsoft Office 365 Security Alert: Critical unauthorized login detected from Russia. Confirm your password immediately within 1 hour to prevent permanent account suspension.",
        "html": "<html><head><title>Microsoft Identity Verification</title></head><body oncontextmenu='return false'><h1>Microsoft</h1><div class='alert'>Urgent security notice</div><form action='http://unrelated-dropzone.biz/collect.php' method='POST'><input type='password' name='credential_harvest'></form></body></html>",
        "label": 1
    },
    {
        "url": "http://secure-chase-portal8821.top/verify-ssn",
        "domain": "secure-chase-portal8821.top",
        "campaign_id": "zero_day_bank_wire_wave",
        "text": "Chase Bank Online: Security verification required. We noticed abnormal high-value wire transfers. Enter your account number, password, and SSN to secure your funds.",
        "html": "<html><head><title>Chase Online Banking</title></head><body><h1>CHASE</h1><p>URGENT: Verify identity immediately</p><form action='http://harvest-vault.top/bank.php' method='POST'><input type='password' name='pass'><input type='password' name='ssn'></form></body></html>",
        "label": 1
    },
    {
        "url": "http://apple-icloud-recovery-2026.club/session/unlock",
        "domain": "apple-icloud-recovery-2026.club",
        "campaign_id": "zero_day_apple_recovery",
        "text": "Apple ID: Your iCloud account is locked due to multiple failed login attempts. Verify credentials and payment method immediately to restore access.",
        "html": "<html><head><title>Apple ID - Manage your Apple account</title></head><body><h1>Apple ID</h1><p>Your Apple ID has been locked</p><form action='http://drop-creds.club/gate.php' method='POST'><input type='password' name='apple_pwd'></form></body></html>",
        "label": 1
    },
    {
        "url": "https://www.nature.com/articles/d41586-024-001",
        "domain": "nature.com",
        "campaign_id": "unseen_legit_scientific",
        "text": "Nature International journal of science latest research papers news comments reviews biotechnology climate",
        "html": "<html><head><title>Nature International Journal of Science</title></head><body><h1>Research Articles</h1><p>Peer-reviewed scientific publications</p></body></html>",
        "label": 0
    },
    {
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP",
        "domain": "mozilla.org",
        "campaign_id": "unseen_legit_tech",
        "text": "MDN Web Docs HTTP Overview Hypertext Transfer Protocol request response status headers",
        "html": "<html><head><title>HTTP Overview - MDN Web Docs</title></head><body><h1>HTTP</h1><p>Documentation for web developers</p></body></html>",
        "label": 0
    }
]


def prepare_datasets(raw_data_path: Path = RAW_DIR / "dataset.json") -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Saves raw benchmark samples and partitions them using domain-aware / campaign-aware splitting.
    Guarantees zero-day evaluation integrity: testing samples belong to completely unseen campaigns/domains!
    """
    with open(raw_data_path, "w", encoding="utf-8") as f:
        json.dump(BENCHMARK_SAMPLES, f, indent=2)

    df = pd.DataFrame(BENCHMARK_SAMPLES)

    # Domain/Campaign-Aware Split
    # Zero-day test campaigns are isolated
    zero_day_campaigns = {
        "zero_day_cloud_impersonation",
        "zero_day_bank_wire_wave",
        "zero_day_apple_recovery",
        "unseen_legit_scientific",
        "unseen_legit_tech"
    }

    test_df = df[df["campaign_id"].isin(zero_day_campaigns)].copy()
    train_df = df[~df["campaign_id"].isin(zero_day_campaigns)].copy()

    train_path = PROCESSED_DIR / "train_domain_aware.json"
    test_path = PROCESSED_DIR / "test_zero_day.json"

    train_df.to_json(train_path, orient="records", indent=2)
    test_df.to_json(test_path, orient="records", indent=2)

    print(f"[*] Dataset prepared successfully.")
    print(f"    Total samples: {len(df)}")
    print(f"    Training samples (known domains/campaigns): {len(train_df)}")
    print(f"    Testing samples (Strictly Unseen Zero-Day campaigns): {len(test_df)}")
    print(f"    Saved to: {train_path} and {test_path}")

    return train_df, test_df


if __name__ == "__main__":
    prepare_datasets()


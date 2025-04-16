import requests
import os
import logging
from datetime import datetime
from io import StringIO
import pandas as pd
import sys
import zipfile
import io


# Output and log paths
blacklist_output_path = "PhishingLink\\Blacklist.txt"
whitelist_output_path = "PhishingLink\\Whitelist.txt"
known_ip_path = "PhishingLink\\knownip.txt"
log_path = "PhishingLink\\task_log.txt"

# Logging setup
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Load existing blacklist
if os.path.exists(blacklist_output_path):
    with open(blacklist_output_path, "r") as f:
        existing_urls = set(line.strip() for line in f.readlines())
else:
    existing_urls = set()

# Result collector
new_urls = set()
new_whitelist_count = set()

try:
    # Pull from OpenPhish
    openphish_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    resp = requests.get(openphish_url, timeout=10)
    resp.raise_for_status()
    openphish_urls = set(resp.text.strip().split("\n"))
    new_openphish = openphish_urls - existing_urls
    new_urls.update(new_openphish)
    logging.info(f"OpenPhish: {len(new_openphish)} new URLs")

except Exception as e:
    logging.exception("Error fetching from OpenPhish")


try:
    # Pull from PhishStats (score >= 4 (basedline))
    phishstats_url = "https://phishstats.info/phish_score.csv"
    resp = requests.get(phishstats_url, timeout=10)
    csv_data = StringIO(resp.text)

    df = pd.read_csv(
        csv_data,
        skiprows=9,
        names=["Date", "Score", "URL", "IP"],
        header=None,
        on_bad_lines="skip",
    )
    df["Score"] = pd.to_numeric(df["Score"], errors="coerce")
    df = df[df["Score"] >= 4]

    stats_urls = set(df["URL"].astype(str))
    new_stats = stats_urls - existing_urls
    new_urls.update(new_stats)
    logging.info(f"PhishStats: {len(new_stats)} new URLs")

except Exception as e:
    logging.exception("Error fetching from PhishStats")

# Pull Whitelist from Tranco-list (Often Broke) P.S We have another source like majestic million we can use but the API is limited and paid access so for the sake of our budget we will not use it
try:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
    }
    id_url = "https://tranco-list.eu/top-1m-id?subdomains=true"
    response = requests.get(id_url, headers=headers)
    response.raise_for_status()
    list_id = response.text.strip()

    # Download Link For Tranco
    zip_url = f"https://tranco-list.eu/download_daily/{list_id}"

    # Zip Extraction
    zip_resp = requests.get(zip_url, headers=headers)
    zip_resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(zip_resp.content)) as z:
        csv_filename = z.namelist()[0]
        with z.open(csv_filename) as f:
            df = pd.read_csv(f, header=None, names=["Rank", "Domain"])

    # Whitelist Endpoint
    whitelist_path = "PhishingLink/Whitelist.txt"

    # Load current whitelist if it exists
    try:
        with open(whitelist_path, "r", encoding="utf-8") as f:
            current_domains = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        current_domains = set()

    # Filter and update
    new_domains = set(df["Domain"].str.strip().str.lower()) - current_domains

    if new_domains:
        with open(whitelist_path, "a", encoding="utf-8") as f:
            for domain in sorted(new_domains):
                f.write(domain + "\n")
        new_whitelist_count.update(new_domains)
        print(f"Added {len(new_domains)} new domains to whitelist.")
        logging.info(f"Tranco: {len(new_domains)} new URLs")
    else:
        print("No new domains to add.")
        logging.info("Tranco: 0 new Domains")

except Exception as e:
    logging.exception("Error fetching or processing Tranco whitelist")


try:
    url = "https://www.spamhaus.org/drop/drop.txt"
    response = requests.get(url)
    lines = response.text.strip().splitlines()

    # Extract new CIDRs from the response
    new_cidrs = set()
    for line in lines:
        if line.startswith(";") or not line.strip():
            continue
        parts = line.split(";")
        if len(parts) >= 1:
            cidr = parts[0].strip()
            new_cidrs.add(cidr)

    # Load existing CIDRs
    if os.path.exists(known_ip_path):
        with open(known_ip_path, "r") as f:
            existing_cidrs = set(line.strip() for line in f if line.strip())
    else:
        existing_cidrs = set()

    # Count Newly Added CIDRs
    actually_new = new_cidrs - existing_cidrs

    # Merge all and save
    combined_cidrs = sorted(existing_cidrs.union(new_cidrs))
    with open(known_ip_path, "w") as f:
        for cidr in combined_cidrs:
            f.write(cidr + "\n")
    logging.info(f"Spamhaus: {len(actually_new)} new CIDRs")

except Exception as e:
    logging.exception("Error fetching from Spamhaus")

if len(actually_new) == 0:
    logging.info("No new CIDRs to add.")

# Log Total URL appended (whitelist + blacklist + CIDRS)
if new_whitelist_count:
    print(f"Added {len(new_whitelist_count)} new domains to {whitelist_output_path}")
    logging.info(f"Appended {len(new_whitelist_count)} total new domains to Whitelist")
else:
    print("No new domains added to Whitelist.")
    logging.info("No new domains to add to Whitelist.")

if new_urls:
    with open(blacklist_output_path, "a") as f:
        for url in sorted(new_urls):
            f.write(url + "\n")
    print(f"Appended {len(new_urls)} new URLs to {blacklist_output_path}")
    logging.info(f"Appended {len(new_urls)} total new URLs to Blacklist")
else:
    print("No new URLs found.")
    logging.info("No new URLs to add.")

sys.exit(0)

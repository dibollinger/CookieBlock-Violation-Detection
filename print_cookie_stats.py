# Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group
# Released under the MIT License
"""
Given the cookie database, computes:
    * Ratio of first-party cookies
    * Ratio of third-party cookies
    * Number of unique cookie names
    * Number of unique cookie domains
For both declared and observed cookies.

Usage:
    print_cookie_stats.py <db_path>
"""
import os
import sqlite3
import re

from docopt import docopt
import logging
from utils import (setupLogger, write_json, write_vdomains, CONSENTDATA_QUERY, JAVASCRIPTCOOKIE_QUERY)

def utud(url: str) -> str:
    """
    Takes a URL or a domain string and transforms it into a uniform format.
    Examples: {"www.example.com", "https://example.com/", ".example.com"} --> "example.com"
    :param url: URL to clean and bring into uniform format
    """
    new_url = url.strip()
    new_url = re.sub("^http(s)?://", "", new_url)
    new_url = re.sub("^www([0-9])?", "", new_url)
    new_url = re.sub("^\\.", "", new_url)
    new_url = re.sub("/$", "", new_url)
    return new_url


def main():
    """
    @return: exit code, 0 for success
    """
    argv = None
    cargs = docopt(__doc__, argv=argv)

    logger = setupLogger(".", logging.INFO)

    logger.info("Extra statistics")

    # Verify that database exists
    database_path = cargs["<db_path>"]
    if not os.path.exists(database_path):
        logger.error("Database file does not exist.")
        return 1

    logger.info(f"Database used: {database_path}")

    # enable dictionary access by column name, access database
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row

    third_party_count = 0
    first_party_count = 0
    unique_domains = set()
    unique_names = set()

    with conn:
        cur = conn.cursor()

        cur.execute(CONSENTDATA_QUERY)
        for row in cur:
            if utud(row["site_url"]) != utud(row["consent_domain"]):
                third_party_count += 1
            else:
                first_party_count += 1

            unique_names.add(row["consent_name"])
            unique_domains.add(utud(row["consent_domain"]))

        cur.close()

    ratioA = first_party_count / (first_party_count + third_party_count)
    ratioB = third_party_count / (first_party_count + third_party_count)
    logger.info(f"Number of declared first-party cookies: {first_party_count} -- {ratioA * 100:.2f}%")
    logger.info(f"Number of declared third-party cookies: {third_party_count} -- {ratioB * 100:.2f}%")
    logger.info(f"Number of unique cookie names in consent table: {len(unique_names)}")
    logger.info(f"Number of unique domains in consent table: {len(unique_domains)}")

    third_party_count = 0
    first_party_count = 0
    unique_domains = set()
    unique_names = set()

    unique_identifiers = set()

    with conn:
        cur = conn.cursor()

        cur.execute(JAVASCRIPTCOOKIE_QUERY)
        for row in cur:
            ident = row["site_url"] + ";" + row["name"] + ";" + row["cookie_domain"] + ";" + row["path"]
            if ident not in unique_identifiers:
                if utud(row["site_url"]) != utud(row["cookie_domain"]):
                    third_party_count += 1
                else:
                    first_party_count += 1
                unique_identifiers.add(ident)

            unique_names.add(row["name"])
            unique_domains.add(utud(row["cookie_domain"]))

        cur.close()

    ratioA = first_party_count / (first_party_count + third_party_count)
    ratioB = third_party_count / (first_party_count + third_party_count)
    logger.info(f"Number of actual first-party cookies: {first_party_count} -- {ratioA * 100:.2f}%")
    logger.info(f"Number of actual third-party cookies: {third_party_count} -- {ratioB * 100:.2f}%")
    logger.info(f"Number of unique cookie names in javascript_cookies table: {len(unique_names)}")
    logger.info(f"Number of unique domains in javascript_cookies table: {len(unique_domains)}")
    return 0

if __name__ == "__main__":
    exit(main())

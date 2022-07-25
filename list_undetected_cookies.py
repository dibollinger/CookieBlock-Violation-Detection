# Copyright (C) 2021-2022 Dino Bollinger, ETH Zürich, Information Security Group
# Released under the MIT License
"""
Using a database of collected cookie + label data, determine all cookies on websites that
have been declared but not been found by the crawler.
----------------------------------
Required arguments:
    <db_path>   Path to database to analyze.
Usage:
    list_undetected_cookies.py <db_path>
"""

from docopt import docopt
import os
import sqlite3
import traceback
import numpy as np

import logging
from utils import (setupLogger, CONSENTDATA_QUERY, get_violation_details_consent_table,
                                       JAVASCRIPTCOOKIE_QUERY, write_json, write_vdomains, canonical_domain)

logger = logging.getLogger("vd")


def main():
    """
    List and count all cookies that have been declared but not been found.
    @return: exit code, 0 for success
    """
    argv = None
    cargs = docopt(__doc__, argv=argv)

    setupLogger(".", logging.INFO)

    logger.info("Listing out undetected cookies...")

    database_path = cargs["<db_path>"]
    if not os.path.exists(database_path):
        logger.error("Database file does not exist.")
        return 1

    logger.info(f"Database used: {database_path}")

    # enable dictionary access by column name
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row

    javascript_cookies = dict()

    # Retrieve data from Javascript Cookies table
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(JAVASCRIPTCOOKIE_QUERY)
            for row in cur:
                if row["cmp_type"] == -1 or row["crawl_state"] != 0:
                    # logger.info(f"No CMP found on domain {row['site_url']}, skipping...")
                    continue
                fpd = row["site_url"]
                if fpd not in javascript_cookies:
                    javascript_cookies[fpd] = set()
                ident = (row["name"], canonical_domain(row["cookie_domain"]))
                javascript_cookies[fpd].add(ident)
            cur.close()
    except (sqlite3.OperationalError, sqlite3.IntegrityError):
        logger.error("A database error occurred:")
        logger.error(traceback.format_exc())
        return -1

    undetected_details = dict()
    undetected_sites = set()
    total_sites = set()
    detected_count = [0,0,0,0,0,0,0]
    undetected_count = [0,0,0,0,0,0,0]
    total_count = 0

    # Compare to data in Consent table. May have multiple domains listed
    with conn:
        cur = conn.cursor()
        cur.execute(CONSENTDATA_QUERY)
        for row in cur:
            # Only count HTTP and HTML cookie types
            if row["type_id"] and (int(row["type_id"]) not in {1, 2}):
                continue
            vdomain = row["site_url"]
            total_sites.add(vdomain)
            total_count += 1

            fpd = row["site_url"]
            consent_domains = row["consent_domain"].split("<br/>")
            found_any = False
            for domain_entry in consent_domains:
                ident = (row["consent_name"], canonical_domain(domain_entry))
                if fpd in javascript_cookies and ident in javascript_cookies[fpd]:
                    found_any = True

            label = int(row["cat_id"])
            if not found_any:
                #logger.info(f"Could not find cookie: {row['consent_name']} ; {row['consent_domain']} from site {row['site_url']}")
                undetected_sites.add(vdomain)

                if label == -1:
                    undetected_count[6] += 1
                if label == 99:
                    undetected_count[5] += 1
                else:
                    undetected_count[label] += 1

                if vdomain not in undetected_details:
                    undetected_details[vdomain] = list()

                undetected_details[vdomain].append(get_violation_details_consent_table(row))
            else:
                if label == -1:
                    detected_count[6] += 1
                if label == 99:
                    detected_count[5] += 1
                else:
                    detected_count[label] += 1

    conn.close()

    logger.info(f"Total cookies declared: {total_count}")
    logger.info(f"Of those found: {detected_count}")
    logger.info(f"Of those not found: {undetected_count}")
    logger.info(f"Undetected ratio: {np.array(undetected_count) / (np.array(undetected_count) + np.array(detected_count))}")
    logger.info(f"Total sites: {len(total_sites)}")
    logger.info(f"Sites with cookies that were not found: {len(undetected_sites)}")
    logger.info(f"Average number of undetected cookies per site: {sum(undetected_count)/len(total_sites):.2f}")
    cmp_count = [0, 0, 0]
    v_per_cmp = [0, 0, 0]
    for url, ic_cookies in undetected_details.items():
        cmp_count[ic_cookies[0]["cmp_type"]] += 1
        for c in ic_cookies:
            assert (c["cmp_type"] >= 0)
            v_per_cmp[c["cmp_type"]] += 1

    logger.info(f"CMP sites: {cmp_count}")
    logger.info(f"Undetected cookies per CMP Type: {v_per_cmp}")
    logger.info(f"Average per CMP type: [{v_per_cmp[0]/cmp_count[0]:.2f},{v_per_cmp[1]/cmp_count[1]:.2f},{v_per_cmp[2]/cmp_count[2]:.2f}]")

    write_json(undetected_details, "undetected_cookies.json")
    write_vdomains(undetected_sites, "undetected_cookie_domains.txt")


    return 0


if __name__ == '__main__':
    exit(main())

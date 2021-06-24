"""
Aggregate violation detections statistics
"""

import json
import numpy as np
import logging
import sys

from statistics import mean, median, stdev

# I want to keep this script parameter-free, so here's how you reliably get the total number of domains:
# Open database in sqlitebrowser, open table "consent_crawl_results", query "crawl_state == 0"
# This will give all domains for which the consent crawl succeeded, which is the set of domains for which we can perform the analysis.
total_domain_count = 29398
known_cats = [(-1,"Unknown"), (0,"Necessary"), (1, "Functionality"), (2, "Analytics"), (3, "Advertising"), (4, "Uncategorised"), (5, "Social Media")]


logger = logging.getLogger("main")
logger.addHandler(logging.StreamHandler(stream=sys.stdout))
logger.addHandler(logging.FileHandler("violation_stats.log", mode='w'))
logger.setLevel(logging.INFO)

def read_json(name) -> dict:
    with open(name, 'r') as fr:
        return json.load(fr)

m1c:dict = read_json("method1_cookies.json")
m2c:dict = read_json("method2_cookies.json")
m3c:dict = read_json("method3_cookies.json")
m4c:dict = read_json("method4_cookies.json")
m5c:dict = read_json("method5_cookies.json")
m6c:dict = read_json("method6_cookies.json")


## Method 7
m7c_n:dict = read_json("method7/method7_cookies_necessary.json")
m7c_f:dict = read_json("method7/method7_cookies_functionality.json")
m7c_an:dict = read_json("method7/method7_cookies_analytics.json")
m7c_ad:dict = read_json("method7/method7_cookies_advertising.json")
m7c_uncat:dict = read_json("method7/method7_cookies_uncategorized.json")
m7c_soc:dict = read_json("method7/method7_cookies_social_media.json")


m7c_temp: set = set()
m7c_dummy: dict = dict()
m7c_all = (m7c_f, m7c_an, m7c_ad, m7c_uncat, m7c_soc)
for m in m7c_all:
    for k in m.keys():
        m7c_temp.add(k)

for m in m7c_temp:
    m7c_dummy[m] = 0

## Method 8
m8c_n:dict = read_json("method8/method8_cookies_necessary.json")
m8c_f:dict = read_json("method8/method8_cookies_functionality.json")
m8c_an:dict = read_json("method8/method8_cookies_analytics.json")
m8c_ad:dict = read_json("method8/method8_cookies_advertising.json")
m8c_uncat:dict = read_json("method8/method8_cookies_uncategorized.json")

m8c_temp = set()
m8c_dummy: dict = dict()
m8c_all = (m8c_f, m8c_an, m8c_ad, m8c_uncat)
for m in m8c_all:
    for k in m.keys():
        m8c_temp.add(k)

for m in m8c_temp:
    m8c_dummy[m] = 0

def general_statistics(mall, title):
    domains_count = [0,0,0,0,0,0, 0, 0]
    avdomains = set()
    domains_distr = dict()

    for mxc, idx in mall:
        avdomains.update(mxc.keys())
        domains_count[idx] = len(mxc.keys())
        for k in mxc.keys():
            domains_distr[k] = 1 if k not in domains_distr else domains_distr[k] + 1

    dcount_np = np.array(domains_count)

    logger.info("-------------------------------")
    logger.info(f"General Statistics -- {title}")
    logger.info("-------------------------------")

    logger.info(f"Total Domain Count: {total_domain_count}")
    logger.info(f"Domains with at least 1 problem: {len(avdomains)} -- {len(avdomains) / total_domain_count * 100:.3f}%")
    logger.info(f"Violation Counts per Method: {dcount_np}")
    logger.info(f"Violation Ratio per Method: {np.round(dcount_np / total_domain_count,5)}")

    dist_sets = dict()
    for k in domains_distr.keys():
        count = domains_distr[k]
        if count not in dist_sets:
            dist_sets[count] = set()
        dist_sets[count].add(k)

    dist_len = {k:len(s) for k, s in dist_sets.items()}

    logger.info(f"Number of sites with the exact count of violations (as key): {dist_len}")
    for i in range(max(dist_len.keys()), 0, -1):
        if i in dist_len:
            logger.info(f"Exactly {i} potential violations: {dist_len[i]} -- {dist_len[i] / total_domain_count * 100:.3f}%")


    cumsum = 0
    for i in range(max(dist_len.keys()), 0, -1):
        cumsum += dist_len[i] if i in dist_len else 0
        logger.info(f"Cumulative Distribution: at least {i} potential violations: {cumsum} -- {cumsum / total_domain_count * 100:.3f}%")


general_statistics([(m1c,0), (m2c,1), (m3c,2), (m4c,3), (m5c,4), (m6c,5), (m7c_dummy, 6), (m8c_dummy, 7)], "All Violation Methods")
general_statistics([(m1c,0), (m2c,1), (m3c,2), (m4c,3), (m6c,5), (m7c_dummy, 6), (m8c_dummy, 7)], "Without Method 5: 'Undeclared Cookies'")

# Method 1-specific Statistics: Misclassified google analytics cookies
logger.info("-------------------------------")
logger.info("Method 1-specific Statistics: Google Analytics misclassified")
logger.info("-------------------------------")
m1_by_cat = {-1:dict(), 0:dict(), 1:dict(), 2:dict(), 3:dict(), 4:dict(), 5:dict()}
for site_url, cookies in m1c.items():
    for c in cookies:
        ldict = m1_by_cat[c["label"]]
        if site_url not in ldict:
            ldict[site_url] = []
        ldict[site_url].append(c)

for idx, name in known_cats:
    logger.info(f"Number of sites with GA misclassified as {name} {len(m1_by_cat[idx].keys())} -- {len(m1_by_cat[idx].keys()) / total_domain_count * 100:.3f}%")


def compute_median_mean_stdev(mxc):
    # median, average
    m_cc_per_site = list()
    for site_url, cookies in mxc.items():
        m_cc_per_site.append(len(cookies))
    logger.info(f"Mean violation cookies per site: {mean(m_cc_per_site):.1f}")
    logger.info(f"Median violation cookies per site: {median(m_cc_per_site):.1f}")
    logger.info(f"Standard Deviation of violation cookies per site: {stdev(m_cc_per_site):.1f}")


compute_median_mean_stdev(m1c)

# Method 2-specific Statistics: Misclassified from Majority
logger.info("-------------------------------")
logger.info("Method 2-specific Statistics: Majority Outliers")
logger.info("-------------------------------")
m2_by_cat = {-1:dict(), 0:dict(), 1:dict(), 2:dict(), 3:dict(), 4:dict(), 5:dict()}
m2_higher_ratio = dict()
m2_by_cat_higher_ratio = {-1:dict(), 0:dict(), 1:dict(), 2:dict(), 3:dict(), 4:dict(), 5:dict()}

for site_url, cookies in m2c.items():
    for c in cookies:
        if 1 < c["majority"] < 3:
            ldict = m2_by_cat[c["label"]]
            if site_url not in ldict:
                ldict[site_url] = []
            ldict[site_url].append(c)

            if c["maj_ratio"] > 0.75:
                ldict = m2_by_cat_higher_ratio[c["label"]]
                if site_url not in ldict:
                    ldict[site_url] = []
                ldict[site_url].append(c)

                if site_url not in m2_higher_ratio:
                    m2_higher_ratio[site_url] = []
                m2_higher_ratio[site_url].append(c)

# median, average
m2_cc_per_site = list()
for site_url, cookies in m2c.items():
    m2_cc_per_site.append(len(cookies))

logger.info(f"Number of domains with outliers > 0.75: {len(m2_higher_ratio.keys())} -- {len(m2_higher_ratio.keys()) / total_domain_count * 100:.2f}%")

for idx, name in known_cats:
    logger.info(f"Number of sites with Outliers from Majority, classified as {name} {len(m2_by_cat[idx].keys())} -- {len(m2_by_cat[idx].keys()) / total_domain_count * 100:.3f}%")

for idx, name in known_cats:
    logger.info(f"Number of sites with Outliers from Majority, ratio >0.75, classified as {name} {len(m2_by_cat_higher_ratio[idx].keys())} -- {len(m2_by_cat_higher_ratio[idx].keys()) / total_domain_count * 100:.3f}%")

compute_median_mean_stdev(m2c)

# Method 3-specifc Statistics: Expiration Date mismatch

logger.info("-------------------------------")
logger.info("Method 3-specific Statistics: Expiration Time Deviation")
logger.info("-------------------------------")


persistent_deviation = dict()
session_as_persistent = dict()
persistent_as_session = dict()

all_expiry_ratios = list()

for site_url, cookies in m3c.items():
    for c in cookies:
        if c["expiry_ratio"]:
            all_expiry_ratios.append(c["expiry_ratio"])

        if c["expiry_diff"] != "persistent_as_session" and c["expiry_diff"] != "session_as_persistent":
            if site_url not in persistent_deviation:
                persistent_deviation[site_url] = []
            persistent_deviation[site_url].append(c)
        elif c["expiry_diff"] == "session_as_persistent":
            if site_url not in session_as_persistent:
                session_as_persistent[site_url] = []
            session_as_persistent[site_url].append(c)
        elif c["expiry_diff"] == "persistent_as_session":
            if site_url not in persistent_as_session:
                persistent_as_session[site_url] = []
            persistent_as_session[site_url].append(c)

logger.info(f"Sites with persistent deviation: {len(persistent_deviation.keys())} -- {len(persistent_deviation.keys()) / total_domain_count * 100 :.3f}%")
logger.info(f"Sites with Persistent as Session: {len(persistent_as_session.keys())} -- {len(persistent_as_session.keys()) / total_domain_count * 100 :.3f}%")
logger.info(f"Sites with Session as Persistent: {len(session_as_persistent.keys())} -- {len(session_as_persistent.keys()) / total_domain_count * 100 :.3f}%")

logger.info("Expiration Ratio Histogram")
logger.info(np.histogram(all_expiry_ratios, bins=[1, 1.5, 1.6, 2, 2.5, 5, 10, 100, 1000, 10000, 10e5, 10e6, 10e7, 10e8, 10e9, np.inf]))

compute_median_mean_stdev(m3c)

logger.info("-------------------------------")
logger.info("Method 4-specific Statistics: Unclassified Cookies")
logger.info("-------------------------------")

count_bins = [*range(0,101), 150, 200, np.inf]


m4_sites_with_count = []
for site_url, cookies in m4c.items():
    m4_sites_with_count.append((len(cookies), site_url))

m4_counts_only = [a[0] for a in m4_sites_with_count]
counts, nbins = np.histogram(m4_counts_only, bins=count_bins)
logger.info("Bins for Histogram:")
logger.info(nbins)
logger.info("Unclassified Cookie count per site histogram")
logger.info(counts)

logger.info(f"Number of sites with at least 5 unclassified cookies: {sum(counts[4:])} -- {sum(counts[4:]) / total_domain_count * 100:.3f}%")
logger.info(f"Number of sites with at least 10 unclassified cookies: {sum(counts[9:])} -- {sum(counts[9:]) / total_domain_count * 100:.3f}%")
logger.info(f"Number of sites with at least 25 unclassified cookies: {sum(counts[24:])} -- {sum(counts[24:]) / total_domain_count * 100:.3f}%")

compute_median_mean_stdev(m4c)

logger.info("-------------------------------")
logger.info("Method 5-specific Statistics: Unclassified Cookies")
logger.info("-------------------------------")

m5_sites_with_count = []
for site_url, cookies in m5c.items():
    m5_sites_with_count.append((len(cookies), site_url))

m5_counts_only = [a[0] for a in m5_sites_with_count]
counts, nbins = np.histogram(m5_counts_only, bins=count_bins)
logger.info("Bins for Histogram:")
logger.info(nbins)
logger.info("Undeclared Cookie count per site histogram")
logger.info(counts)
logger.info(f"Number of sites with at least 5 undeclared cookies: {sum(counts[4:])} -- {sum(counts[4:]) / total_domain_count * 100:.3f}%")
logger.info(f"Number of sites with at least 10 undeclared cookies: {sum(counts[9:])} -- {sum(counts[9:]) / total_domain_count * 100:.3f}% ")
logger.info(f"Number of sites with at least 25 undeclared cookies: {sum(counts[24:])} -- {sum(counts[24:]) / total_domain_count * 100:.3f}% ")

compute_median_mean_stdev(m5c)

logger.info("-------------------------------")
logger.info("Method 6-specific Statistics: Multiple Declarations")
logger.info("-------------------------------")

m6_sites_necessary = dict()
m6_sites_functionality = dict()
for site_url, cookies in m6c.items():
    for c in cookies:
        if ((c["label"] > 1 and c["label"] < 3) and (0 in c["additional_labels"])) or (c["label"] == 0 and (2 in c["additional_labels"] or 3 in c["additional_labels"])):
            if site_url not in m6_sites_necessary:
                m6_sites_necessary[site_url] = []
            m6_sites_necessary[site_url].append(c)

        if ((c["label"] > 1 and c["label"] < 3) and (1 in c["additional_labels"])) or (c["label"] == 1 and (2 in c["additional_labels"] or 3 in c["additional_labels"])):
            if site_url not in m6_sites_functionality:
                m6_sites_functionality[site_url] = []
            m6_sites_functionality[site_url].append(c)


logger.info(f"Number of sites with necessary cookies that have 'analytics' or 'advertising' as dual label: {len(m6_sites_necessary.keys())} -- {len(m6_sites_necessary.keys()) / total_domain_count * 100:.3f}%")
logger.info(f"Number of sites with functional cookies that have 'analytics' or 'advertising' as dual label: {len(m6_sites_functionality.keys())} -- {len(m6_sites_functionality.keys()) / total_domain_count * 100:.3f}%")

compute_median_mean_stdev(m6c)

m1_strict = set()
m1_strict.update(m1_by_cat[0].keys())
m1_strict.update(m1_by_cat[1].keys())

m2_strict = set()
m2_strict.update(m2_by_cat_higher_ratio[0].keys())
m2_strict.update(m2_by_cat_higher_ratio[1].keys())

m3_strict = set()
m3_strict.update(persistent_deviation.keys())
m3_strict.update(session_as_persistent.keys())

m4_strict = set()
m4_strict.update([a[1] for a in m4_sites_with_count if a[0] > 0])

m5_strict = set()
m5_strict.update([a[1] for a in m5_sites_with_count if a[0] > 5])

m6_strict = set()
m6_strict.update(m6_sites_necessary.keys())
m6_strict.update(m6_sites_functionality.keys())

## Unused strict variant of the statistics

#def generic_stats_strict(mall, name):
#    logger.info("-------------------------------")
#    logger.info(f"Stricter Analysis: {name}")
#    logger.info("Method 1: Only Analytics -> Functionality/Necessary")
#    logger.info("Method 2: Only (Majority: Advertising/Analytics) -> (Outlier: Functionality/Necessary)")
#    logger.info("Method 3: Excluded Persistent Declarations for Session Cookies")
#    logger.info("Method 4: No changes")
#    logger.info("Method 5: Minimum threshold of 5 missing declarations")
#    logger.info("Method 6: Only report multiple labels if one is 'advertising/analytics', the other is 'necessary/functional'")
#    logger.info("-------------------------------")
#
#    avdomains = set()
#    dcount = []
#    domains_distr = dict()
#    for mxc in mall:
#        avdomains.update(mxc)
#        dcount.append(len(mxc))
#        for k in mxc:
#            domains_distr[k] = 1 if k not in domains_distr else domains_distr[k] + 1
#
#    dcount_np = np.array(dcount)
#
#    logger.info(f"Total Domain Count: {total_domain_count}")
#    logger.info(f"Domains with at least 1 problem: {len(avdomains)} -- {len(avdomains) / total_domain_count * 100:.3f}%")
#    logger.info(f"Violation Counts per Method: {dcount_np}")
#    logger.info(f"Violation Ratio per Method: {np.round(dcount_np / total_domain_count,5)}")
#
#    dist_sets = dict()
#    for k in domains_distr.keys():
#        count = domains_distr[k]
#        if count not in dist_sets:
#            dist_sets[count] = set()
#        dist_sets[count].add(k)
#
#    dist_len = {k:len(s) for k, s in dist_sets.items()}
#
#    logger.info(f"Number of sites with the exact count of violations (as key): {dist_len}")
#    for i in range(max(dist_len.keys()), 0, -1):
#        if i in dist_len:
#            logger.info(f"Exactly {i} potential violations: {dist_len[i]} -- {dist_len[i] / total_domain_count * 100:.3f}%")
#
#
#    cumsum = 0
#    for i in range(max(dist_len.keys()), 0, -1):
#        cumsum += dist_len[i] if i in dist_len else 0
#        logger.info(f"Cumulative Distribution: at least {i} potential violations: {cumsum} -- {cumsum / total_domain_count * 100:.3f}%")
#
#generic_stats_strict([m1_strict, m2_strict, m3_strict, m4_strict, m5_strict, m6_strict], "All Methods")


def m78_check(mxc_f, mxc_an, mxc_ad, mxc_uncat, mxc_soc, total_num):
    logger.info(f"total domains of that run: {total_num}")
    all_others = set()
    all_others.update(mxc_f.keys())
    all_others.update(mxc_an.keys())
    all_others.update(mxc_ad.keys())
    all_others.update(mxc_uncat.keys())
    if mxc_soc:
        all_others.update(mxc_soc.keys())

    logger.info(f"Number of sites that set any cookie other than 'necessary': {len(all_others)} -- {len(all_others) / total_num * 100:.2f}%")

    adan = set()
    adan.update(mxc_an.keys())
    adan.update(mxc_ad.keys())

    logger.info(f"Number of sites that set 'advertising' and 'analytics' cookies: {len(adan)} -- {len(adan) / total_num * 100:.2f}%")

logger.info("-------------------------------")
logger.info("Method 7-specific Statistics: Implicit Consent")
logger.info("-------------------------------")

m78_check(m7c_f, m7c_an, m7c_ad, m7c_uncat, m7c_soc, total_domain_count)


logger.info("-------------------------------")
logger.info("Method 8-specific Statistics: Ignored Consent Choices")
logger.info("-------------------------------")

m78_check(m8c_f, m8c_an, m8c_ad, m8c_uncat, None, total_domain_count)

logger.info("-------------------------------")
logger.info("Method 8-specific Statistics: Ignored Consent Choices ( Only Cookiebot) ")
logger.info("-------------------------------")
m78_check(m8c_f, m8c_an, m8c_ad, m8c_uncat, None, 9446)


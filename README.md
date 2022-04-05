# GDPR Violation Detection for Consent Management Platforms

This repository provides the scripts that were used for the techniques of GDPR violation detection
described in the master thesis report __"Analyzing Cookies Compliance with the GDPR"__, as well as the
paper __"Automating Cookie Consent and GDPR Violation Detection"__. 

The paper can be found here:

https://karelkubicek.github.io/post/cookieblock.html

And the master thesis report can be found at the following page:

https://www.research-collection.ethz.ch/handle/20.500.11850/477333

Particularly relevant to this repository is __Section 7: Automatic Violation Detection__ of the 
master thesis report. Here, six analyses are described with which to perform detection of potential 
GDPR violations, along with the legal justification as to why these can be considered potential 
violations.

In order to use the scripts in this folder, a database as collected by the 
"CookieBlock Consent Crawler" is  required. The code for this can be found in the following 
repository:

https://github.com/dibollinger/CookieBlock-Consent-Crawler

The data collected during the thesis can be found in the following Zenodo record:

https://zenodo.org/record/6413531

## Setup and Requirements

No installation or setup necessary. For library requirements, see `requirements.txt`.

Each script can be executed independently. Required input is usually a database created and filled 
by the CookieBlock Consent Crawler. More information is given below.

## Repository Contents

* `violation_stats/`: Target folder for all outputs.
  * `violation_stats/violation_stats.py`: Used to compute the statistics from the outputs of the scripts listed below.
* `list_undetected_cookies.py`: Lists out all cookie declarations that have no matching observed cookie. 
  * Usage: `list_undetected_cookies.py <db_path>`
* `method1_wrong_label.py`: Finds all instances of a known cookie with a mismatched class. Corresponds to method 1 in the report.
  * Usage: `method1_wrong_label.py method1_wrong_label.py <db_path> [<name_pattern> <domain_pattern> <expected_label>]`
* `method2_majority_deviation.py`: Computes the majority class for a cookie, then finds all deviations from the majority. Corresponds to method 2 in the report.
  * Usage: `method2_majority_deviation.py <db_path>`
* `method3_inconsistent_expiry.py`: Finds all cookies where the expiration date deviates by 1.5 times the declared date. Corresponds to method 3 in the report.
  * Usage: `method3_inconsistent_expiry.py <db_path>`
* `method4_unclassified_cookies.py`: Finds all unclassified cookies. Corresponds to method 4 in the report.
  * Usage: `method4_unclassified_cookies.py <db_path>`
* `method5_undeclared_cookies.py`: Finds all cookies that have been encountered but not declared. Corresponds to method 5 in the report.
  * Usage: `method5_undeclared_cookies.py <db_path>`
* `method6_contradictory_labels.py`: Finds all cookies that were given multiple contradictory purposes by the CMP. Method 6 in the report.
  * Usage: `method6_contradictory_labels.py <db_path>`
* `method7_implicit_consent.py`: Finds all cookies that were set, even when no consent was given. Requires a special website crawl. Only described in the paper, not in the report.
  * Usage: `method7_implicit_consent.py <db_path>`
* `method8_ignored_choices.py`: Finds all cookies that were set despite being denied consent. Requires a special website crawl. Only described in the paper, not in the report.
  * Usage: `method8_ignored_choices.py <db_path>`
* `print_cookie_stats.py`: Computes the ratio of first-party cookies, the ratio of third-party cookies, the number of unique cookie names as well as the number of unique cookie domains
* `utils.py`: Contains shared script functions.

## Credits

This repository was created as part of the master thesis __"Analyzing Cookies Compliance with the GDPR"__, 
which can be found at:

https://www.research-collection.ethz.ch/handle/20.500.11850/477333

as well as the paper __"Automating Cookie Consent and GDPR Violation Detection"__, which can be found at:

https://karelkubicek.github.io/post/cookieblock.html

__Thesis supervision and co-authors:__
* Karel Kubicek
* Dr. Carlos Cotrini
* Prof. Dr. David Basin
* Information Security Group at ETH Zürich

---
See also the following repositories for other components that were developed as part of the thesis/paper:

* [CookieBlock Browser Extension](https://github.com/dibollinger/CookieBlock)
* [OpenWPM-based Consent Crawler](https://github.com/dibollinger/CookieBlock-Consent-Crawler)
* [Cookie Classifier](https://github.com/dibollinger/CookieBlock-Consent-Classifier)
* [Prototype Consent Crawler](https://github.com/dibollinger/CookieBlock-Crawler-Prototype)
* [Collected Data](https://zenodo.org/record/5633670)

## License

__Copyright © 2021 Dino Bollinger, Department of Computer Science at ETH Zürich, Information Security Group__

MIT License, see included LICENSE file

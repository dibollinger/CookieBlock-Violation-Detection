# GDPR Violation Detection for Consent Management Platforms

This repository provides the scripts that were used for the techniques of GDPR violation detection
described in the master thesis report "Analyzing Cookies Compliance with the GDPR". The thesis report
can be found at the following page:

https://www.research-collection.ethz.ch/handle/20.500.11850/477333

Particularly relevant to this repository is __Section 7: Automatic Violation Detection__. Here, six analyses
are described with which to perform detection of potential GDPR violations, along with the legal justification
as to why these can be considered violations in the first place.

In order to use the scripts in this folder, a database as collected by the "CookieBlock Consent Crawler" is 
required. The code for this can be found in the following repository:

https://github.com/dibollinger/CookieBlock-Consent-Crawler

Additionally, the data collected during the thesis can be found in the following Google Drive folder:

https://drive.google.com/drive/folders/1P2ikGlnb3Kbb-FhxrGYUPvGpvHeHy5ao

## Repository Contents

* `violation_stats/`: Target folder for all outputs.
* `list_undetected_cookies.py`: Lists out all cookie declarations that have no matching observed cookie.
* `method1_wrong_label.py`: Finds all instances of a known cookie with a mismatched class. Corresponds to method 1 in the report.
* `method2_majority_deviation.py`: Computes the majority class for a cookie, then finds all deviations from the majority. Corresponds to method 2 in the report.
* `method3_inconsistent_expiry.py`: Finds all cookies where the expiration date deviates by 1.5 times the declared date. Corresponds to method 3 in the report.
* `method4_unclassified_cookies.py`: Finds all unclassified cookies. Corresponds to method 4 in the report.
* `method5_undeclared_cookies.py`: Finds all cookies that have been encountered but not declared. Corresponds to method 5 in the report.
* `method6_contradictory_labels.py`: Finds all cookies that were given multiple contradictory purposes by the CMP. Method 6 in the report.
* `utils.py`: Contains shared script functions.

## Credits

This repository was created as part of the master thesis __"Analyzing Cookies Compliance with the GDPR"__, 
which can be found here:

https://www.research-collection.ethz.ch/handle/20.500.11850/477333

__Thesis Supervision and Assistance:__
* Karel Kubicek
* Dr. Carlos Cotrini
* Prof. Dr. David Basin
* Information Security Group at ETH Zürich

---
See also the following repositories for other components that were developed as part of the thesis:

* [CookieBlock Browser Extension](https://github.com/dibollinger/CookieBlock)
* [OpenWPM-based Consent Crawler](https://github.com/dibollinger/CookieBlock-Consent-Crawler)
* [Cookie Classifier](https://github.com/dibollinger/CookieBlock-Consent-Classifier)
* [Prototype Consent Crawler](https://github.com/dibollinger/CookieBlock-Crawler-Prototype)
* [Collected Data](https://drive.google.com/drive/folders/1P2ikGlnb3Kbb-FhxrGYUPvGpvHeHy5ao)

## License

__Copyright © 2021 Dino Bollinger, Department of Computer Science at ETH Zürich, Information Security Group__

MIT License, see included LICENSE file
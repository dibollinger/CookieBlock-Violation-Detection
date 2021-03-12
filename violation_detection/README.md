# Violation Detection Scripts
The scripts in this folder correspond to section 7 of the master thesis report on GDPR compliance.

Each script extracts evidence for different types of violations. 

## Folder Contents
* `violation_stats/`: Target folder for outputs.
* `list_undetected_cookies.py`: Lists out all cookie declarations that have no matching cookie.
* `method1_wrong_label.py`: Finds all instances of a known cookie with a mismatched class.
* `method2_majority_deviation.py`: Computes the majority class for a cookie, then finds all deviations from the majority.
* `method3_inconsistent_expiry.py`: Finds all cookies where the expiration date deviates by 1.5 times the declared date.
* `method4_unclassified_cookies.py`: Finds all unclassified cookies.
* `method5_undeclared_cookies.py`: Finds all cookies that have been encountered but not declared.
* `method6_contradictory_labels.py`: Finds all cookies that were given multiple contradictory purposes by the CMP.
* `utils.py`: Contains shared script functions.
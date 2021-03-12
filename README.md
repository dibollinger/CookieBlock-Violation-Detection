# Other Scripts used in the Development of CookieBlock

This repository contains scripts that were used in combination with the other repositories:
* Domain lists, filtering duplicate domains and retrieving potential crawl targets from Cookiepedia.
* Extracting content and crawl statistics and the training data in JSON format from the crawl database.
* Run additional statistics scripts on the extracted training data, and determine Cookiepedia baseline performance.
* Create resource files to aid in feature extraction for the classifier.
* Gather evidence for potential violations given a crawl database as produced by the Consent Crawler.

## Repository Contents

* `cookiedata_analysis/`: Contains scripts to analyze the training data and to produce the Cookiepedia baseline performance.
* `database_scripts/`: Contains scripts to extract statistics from the database (using SQL statements) and to match consent table with cookie data, to produce the training input for the classifier.
* `domain_sources/`: Contains the domains used for crawling the database as well as scripts to retrieve them and to prune duplicates
* `feature_resources/`: Contains scripts to produce resource files used with the feature extraction of the classifier.
* `violation_detection/`: Contains scripts to automatically gather evidence for potential GDPR violations.

----
## Credits and License

Copyright © 2021 Dino Bollinger
Under the MIT License
See included LICENSE file

These scripts were created as part of a master thesis on GDPR Compliance, 
and is part of a series of repositories for the CookieBlock browser extension:

TODO

Thanks go to:
* Karel Kubicek
* Dr. Carlos Cotrini
* Prof. Dr. David Basin
* The Institute of Information Security at ETH Zürich
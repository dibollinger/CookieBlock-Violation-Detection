# Author: Dino Bollinger
# LICENSE: MIT
"""
Takes as input a list of text files containing one valid URL per line,
and attempts to prune duplicates netlocators (i.e. duplicate domains).
Outputs a filtered list of URLs.

Usage:
    filter_duplicate_netlocs.py (--file <FILE>)... (--out <OUT>)

Options:
    -f --file <FILE>   File to draw domains from (1 per line)
    -o --out <OUT>     Outfile path
    -h --help          Display this information.
"""


import re
import os
import tldextract

from urllib.parse import urlparse
from docopt import docopt

domains = set()
urls = list()

extract = tldextract.TLDExtract()

def unique_extract(line: str):
    url = line.strip()
    d = urlparse(url)[1] # get netloc
    d = re.sub("^www\\.", "", d)
    d = re.sub(":[0-9]*", "", d)
    d = extract(d).domain
    if d not in domains:
        domains.add(d)
        urls.append(url)
    else:
        print(f"duplicate domain for: {url}")


def main() -> int:

    argv = None
    args = docopt(__doc__, argv=argv)

    valid_paths = []
    output_path = args["--out"]

    for fpath in args["--file"]:
        if os.path.exists(fpath):
            valid_paths.append(fpath)

    for v in valid_paths:
        with open(v, 'r') as fd:
            for l in fd:
                unique_extract(l)

    print(f"Number of unique URLs: {len(urls)}")

    with open(output_path, 'w') as fd:
        for u in urls:
            fd.write(u + "\n")

    return 0

if __name__ == "__main__":
    main()






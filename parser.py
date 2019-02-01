import json
import os
import re
from collections import defaultdict
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from typing import List, Tuple, Pattern

from bs4 import BeautifulSoup
from bs4.element import Tag, NavigableString

from logger import create_logger

data_dir = 'data'
logger = create_logger(__name__)


def clean_vulnerability(v):
    s = "\u000a\u2018\u2019\u201c\u201d\u00a0"
    for c in s:
        v = v.replace(c, '')
    return v


def parse_anchor_title(t: str) -> Tuple[str, str]:
    if t.startswith('http://'):
        t = re.sub(r'(http://.*html\s?,\s?)', '', t)

    delimiter = re.findall(r'CWE-\s?\d+(.)\s?\w+', t)
    try:
        cwe, vulnerability = (t.split(',')[0].split(delimiter[0])[:2])
    except ValueError:
        cwe, vulnerability = (t.split(',')[2].split(':'))
    vulnerability = vulnerability.split('.')[0]
    return cwe, vulnerability


def parse_cvss(tag: Tag, ends: List[Tag]) -> float or None:

    def get_score(score_found: List[str]) -> float or None:
        if score_found:
            scores = score_found[0]
            if scores:
                return float(scores[0])
            else:
                return (float(scores[0]) + float(scores[1])) / 2.0
        return None

    def find_recursively(cur: Tag or NavigableString,
                         pattern: Pattern) -> int or None:
        while cur is not None and cur not in ends:
            text = cur
            if isinstance(cur, Tag):
                text = cur.text

            found = pattern.findall(text)
            score_ = get_score(found)
            if score_:
                return score_
            cur = cur.next_sibling
        return None

    score_patterns = [
        re.compile(r'score of (\d+\.?\d?)', flags=re.I),
        re.compile(r'range from (\d+\.?\d?).*(\d+\.?\d?)', flags=re.I),
        re.compile(r'CVSS: (\d+\.?\d?)-(\d+\.?\d?)')
    ]

    for score_pattern in score_patterns:
        score = find_recursively(tag, score_pattern)
        if score is not None:
            return score
    return None


def parse_advisory_vulnerabilities(soup: BeautifulSoup) -> List:
    vulnerabilities = []
    overview_p = re.compile('VULNERABILITY OVERVIEW', flags=re.I)
    end_texts = (
        'VULNERABILITY DETAILS', 'RESEARCHER', 'BACKGROUND', 'MITIGATION',
    )
    ends = set()
    for tag in ('h2', 'h3'):
        for text in end_texts:
            end_tag = soup.find(tag, text=text, flags=re.I)
            if end_tag is not None:
                ends.add(end_tag)

    start = soup.find('h3', text=overview_p)
    if start is None:
        start = soup.find('h2', text=overview_p)

    if start is not None:
        cur = start
        ends = []

        while cur is not None and cur not in ends:
            cwe = vulnerability = anchor = None
            if isinstance(cur, Tag):
                anchor = cur.find('a')

            if (anchor is not None and
                ('title' in anchor.attrs or
                 ('href' in anchor.attrs and
                  anchor.attrs['href'].startswith('https://cwe.mitre.org')))):
                if ('title' in anchor.attrs and
                    'class' in anchor.attrs and
                    'see-footnote' in anchor.attrs['class']):
                    title = anchor.attrs['title'].strip()
                    if 'nvd' in title.lower() or 'cwe' not in title.lower():
                        pass
                    elif title.startswith('CWE-'):
                        cwe, vulnerability = parse_anchor_title(title)
                    else:
                        if 'CWE-' in title:
                            cwe, vulnerability = parse_anchor_title(title)
                            if '.' in cwe:
                                cwe = cwe.split('. ')[1]
                        else:
                            cwe = None
                            vulnerability = cur.contents[0]
                            if isinstance(vulnerability, Tag):
                                vulnerability = vulnerability.contents[0]
                            cwe_number = re.findall(r'(\d+)\.html', title)
                            if cwe_number:
                                cwe = 'CWE-' + cwe_number[0]
                else:
                    text = anchor.text.strip()
                    if text:
                        child_anchor = anchor.find(
                            'a', attrs={'class': 'see-footnote'})
                        if (child_anchor is not None and
                            'title' in child_anchor.attrs and
                            'CWE-' in child_anchor.attrs['title']):
                            cwe, vulnerability = (
                                parse_anchor_title(child_anchor.attrs['title']))
                        elif len(text) > 5:
                            cwe_number = re.findall(r'CWE[\s-]+?(\d+)', text)[0]
                            cwe = 'CWE-' + cwe_number
                            vulnerability = re.sub(r'CWE[\s-]+?\d+', '', text)

            if cwe and vulnerability:
                cvss = parse_cvss(cur, ends)
                vulnerabilities.append(
                    dict(cwe=cwe.strip(),
                         cvss=cvss,
                         vulnerability=clean_vulnerability(
                             vulnerability.strip())
                         ))
            cur = cur.next_sibling

    return vulnerabilities


def parse_advisory(vendor: str, html_path: str) -> Tuple[str, List]:
    with open(html_path, 'r') as f:
        html = f.read()
    soup = BeautifulSoup(html, 'lxml')
    return vendor, parse_advisory_vulnerabilities(soup)


def parse():
    pool = ThreadPoolExecutor()
    futures = []
    advisory_html_paths = []
    data = defaultdict(list)

    for vendor in os.listdir(data_dir):
        vendor_dir = os.path.join(data_dir, vendor)
        if not os.path.isdir(vendor_dir):
            continue

        for fn in os.listdir(vendor_dir):
            advisory_html_paths.append((vendor, os.path.join(vendor_dir, fn)))

    for (vendor, html_path) in advisory_html_paths:
        futures.append(pool.submit(parse_advisory, vendor, html_path))

    for fs in as_completed(futures):
        vendor, vulnerabilities = fs.result()
        data[vendor].extend(vulnerabilities)

    with open('./app/src/vulnerabilities.json', 'w') as f:
        json.dump(data, f)


if __name__ == '__main__':
    parse()

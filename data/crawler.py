import collections
import json
import os
from concurrent import futures

import bs4

from data.utils import create_new_session, get_last_page

host = 'https://www.us-cert.gov'
session = create_new_session()
data_dir = os.path.dirname(os.path.abspath(__file__))


def get_advisories_by_vendor():
    url = f'{host}/ics/advisories-by-vendor-last-revised-date'
    r = session.get(url)
    last_page = get_last_page(r.text)
    advisories_by_vendor = collections.defaultdict(list)

    for page in range(last_page):
        r = session.get(url, params=dict(page=page))
        soup = bs4.BeautifulSoup(r.text, 'lxml')
        items = soup.select('div.item-list')
        for item in items:
            vendor_name = item.find('h3').text.strip()
            if ',' in vendor_name:
                vendor_names = map(lambda s: s.strip(), vendor_name.split(','))
            else:
                vendor_names = [vendor_name]

            for vendor_name in vendor_names:
                advisories = item.find_all('a')
                for adv in advisories:
                    href = adv.attrs['href']
                    advisories_by_vendor[vendor_name].append(href)
    return advisories_by_vendor


def save_page(vendor, url, doc_id):
    r = session.get(url)
    html_path = os.path.join(data_dir, 'advisories', vendor, f'{doc_id}.html')
    with open(html_path, 'w') as f:
        f.write(r.text)
    return vendor, doc_id


def crawl_advisories():
    jobs = []
    pool = futures.ThreadPoolExecutor()
    advisories = {}

    print('[*] Getting advisories...', end='')
    advisories_by_vendor = get_advisories_by_vendor()
    print('Done')

    for vendor in advisories_by_vendor:
        os.makedirs(os.path.join(data_dir, 'advisories', vendor), exist_ok=True)

    for vendor in advisories_by_vendor:
        for href in advisories_by_vendor[vendor]:
            url = f'{host}{href}'
            doc_id = href.split('/')[-1].upper()
            jobs.append(pool.submit(save_page, vendor, url, doc_id))

    for job in futures.as_completed(jobs):
        vendor, doc_id = job.result()
        advisories[doc_id] = dict(
            vendor=vendor,
            path=os.path.join('data', 'advisories', vendor, f'{doc_id}.html'),
        )
        print(f'[+] {vendor}/{doc_id}.html')

    with open(os.path.join(data_dir, 'advisories.json'), 'w') as f:
        json.dump(advisories, f)
    print('[*] Done')


if __name__ == '__main__':
    crawl_advisories()

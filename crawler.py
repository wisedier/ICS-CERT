import os
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from typing import List

import requests
from bs4 import BeautifulSoup

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'
}
host = 'https://ics-cert.us-cert.gov'
base_url = host + '/advisories-by-vendor'
last_page = 43


def get_vendor_pages(vendor: str, hrefs: List[str], titles: List[str]):
    client = requests.session()
    dir_path = os.path.join('data', vendor)
    os.makedirs(dir_path, exist_ok=True)

    for i, (href, title) in enumerate(zip(hrefs, titles)):
        url = host + href
        r = client.get(url, headers=headers)
        html_path = os.path.join(dir_path, '%d.html' % i)
        with open(html_path, 'w') as f:
            f.write(r.text)
    client.close()
    return vendor


def save_pages():
    futures = []
    pool = ThreadPoolExecutor()

    url = host + '/advisories-by-vendor'
    r = requests.get(url, headers=headers)
    soup = BeautifulSoup(r.text, 'lxml')
    items = soup.select('.item-list')

    for item in items:
        vendor = item.find('h3').text
        advisories = item.find_all('a')
        hrefs = map(lambda a: a.attrs['href'], advisories)
        titles = map(lambda a: a.text, advisories)
        fs = pool.submit(get_vendor_pages, vendor, hrefs, titles)
        futures.append(fs)

    for fs in as_completed(futures):
        vendor = fs.result()
        print('[*] Complete %s' % vendor)


if __name__ == '__main__':
    save_pages()

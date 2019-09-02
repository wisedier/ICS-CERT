import bs4
import requests


def create_new_session():
    session = requests.Session()
    user_agent = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "snap Chromium/78.0.3887.7 Chrome/78.0.3887.7 Safari/537.36"
    )
    session.headers.update({'User-Agent': user_agent})
    return session


def get_last_page(html):
    soup = bs4.BeautifulSoup(html, 'lxml')
    last_pager = soup.select_one('.pager__item.pager__item--last > a')
    if last_pager is None:
        return None
    return int(last_pager.attrs['href'].split('=')[1]) + 1

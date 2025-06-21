import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
from database import create_database, save_vulnerability, count_vulnerabilities

BASE_URL = "https://pocorexp.nsa.im/"

def get_year_links():
    """
    Собирает ссылки на страницы с уязвимостями по годам из toc.html.
    """
    toc_url = urljoin(BASE_URL, 'toc.html')
    try:
        response = requests.get(toc_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе к {toc_url}: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    year_links = []
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.endswith('.html') and href[:-5].isdigit() and len(href[:-5]) == 4:
            full_url = urljoin(BASE_URL, href)
            year_links.append(full_url)
            
    return sorted(list(set(year_links)), reverse=True)

def parse_vulnerabilities(year_url):
    """
    Парсит уязвимости со страницы года и сохраняет их в базу данных.
    """
    print(f"Парсинг страницы: {year_url}")
    try:
        response = requests.get(year_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе к {year_url}: {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    year = year_url.split('/')[-1].split('.')[0]
    
    vulnerabilities = {}
    for h2 in soup.find_all('h2'):
        cve_id_tag = h2.find('a', class_='header')
        if not cve_id_tag:
            continue
            
        cve_id = cve_id_tag.parent.get('id')
        
        description_tag = h2.find_next_sibling('p')
        description = description_tag.text.strip() if description_tag else 'N/A'

        ul_tag = h2.find_next_sibling('ul')
        if ul_tag:
            poc_links = [urljoin(BASE_URL, a['href']) for a in ul_tag.find_all('a', href=True)]
        else:
            poc_links = []

        if cve_id and cve_id.startswith('cve-'):
            cve_id_upper = cve_id.upper()
            
            if cve_id_upper not in vulnerabilities:
                vulnerabilities[cve_id_upper] = {'description': description, 'links': []}
            
            vulnerabilities[cve_id_upper]['links'].extend(poc_links)

    for cve_id, data in vulnerabilities.items():
        save_vulnerability(year, cve_id, data['description'], data['links'])
        print(f"Обработана уязвимость: {cve_id}")

def main():
    """
    Главная функция для запуска парсера.
    """
    print("Парсер запущен.")
    create_database()
    links = get_year_links()
    if links:
        for link in links:
            parse_vulnerabilities(link)
    else:
        print("Ссылки по годам не найдены.")
    total_vulnerabilities = count_vulnerabilities()
    print(f"Парсинг завершен. Всего найдено записей: {total_vulnerabilities}")

if __name__ == '__main__':
    main()
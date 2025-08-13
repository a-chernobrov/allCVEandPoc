import os
import requests
from database import get_all_cve_data, cve_exists

def download_and_extract_all_cve():
    """
    Downloads and extracts all CVE repositories from the database.
    """
    download_folder = 'download'
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)

    cve_list = get_all_cve_data()

    for cve_id, repo_url in cve_list:
        if repo_url:
            try:
                owner, repo_name = repo_url.split('/')[-2:]
            except (ValueError, AttributeError):
                print(f"Invalid repo URL format: {repo_url}. Skipping...")
                continue
        else:
            print(f"Skipping entry with None repo_url for CVE: {cve_id}")
            continue
        
        cve_dir = os.path.join(download_folder, cve_id)
        if not os.path.exists(cve_dir):
            os.makedirs(cve_dir)

        file_name = f"{owner}-{repo_name}.zip"
        file_path = os.path.join(cve_dir, file_name)

        if os.path.exists(file_path):
            print(f"File {file_name} already exists in {cve_dir}. Skipping...")
            continue

        archive_url_main = f"{repo_url}/archive/refs/heads/main.zip"
        archive_url_master = f"{repo_url}/archive/refs/heads/master.zip"

        try:
            response = requests.get(archive_url_main, stream=True)
            if response.status_code != 200:
                response = requests.get(archive_url_master, stream=True)

            response.raise_for_status()

            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print(f"Downloaded archive: {file_name} to {cve_dir}")

        except requests.exceptions.RequestException as e:
            print(f"Error downloading {repo_url}: {e}")

if __name__ == '__main__':
    download_and_extract_all_cve()
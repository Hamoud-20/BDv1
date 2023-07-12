import argparse
import os
import requests
import time
import psutil
from prettytable import PrettyTable
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

print('\033[34;1m' + """  

██╗███╗░░██╗████████╗███████╗███████╗██████╗░███████╗████████╗███████╗░█████╗░████████╗
██║████╗░██║╚══██╔══╝██╔════╝╚════██║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝
██║██╔██╗██║░░░██║░░░█████╗░░░░███╔═╝██║░░██║█████╗░░░░░██║░░░█████╗░░██║░░╚═╝░░░██║░░░
██║██║╚████║░░░██║░░░██╔══╝░░██╔══╝░░██║░░██║██╔══╝░░░░░██║░░░██╔══╝░░██║░░██╗░░░██║░░░
██║██║░╚███║░░░██║░░░███████╗███████╗██████╔╝███████╗░░░██║░░░███████╗╚█████╔╝░░░██║░░░
╚═╝╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚══════╝╚═════╝░╚══════╝░░░╚═╝░░░╚══════╝░╚════╝░░░░╚═╝░░░
 
                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                   +        ..| IntezDetect v1.0 |..      +
                   -                                      -
                   -              By: Hamoud Alharbi      -
                   +         Twitter: @Hamoud__2          +
                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

""" + '\033[0m')

                                                                             


API_KEY = 'd3c883a0-4507-4713-a6d2-1e30e6ac695d'
INTEZER_API_URL = 'https://analyze.intezer.com/api/v2-0'
MAX_WORKERS = 5  # Number of concurrent threads

def color_malicious(text):
    if "malicious" in text.lower():
        return text.replace("malicious", colored("malicious", "red"))
    return text

def display_results(results):
    result = results.get('result', {})

    table = PrettyTable()
    table.field_names = ["Attribute", "Value"]

    table.add_row([colored("Analysis ID", "cyan"), color_malicious(result.get("analysis_id", "N/A"))])
    table.add_row([colored("Analysis Time", "cyan"), color_malicious(result.get("analysis_time", "N/A"))])
    table.add_row([colored("Analysis URL", "cyan"), color_malicious(result.get("analysis_url", "N/A"))])
    table.add_row([colored("File Name", "cyan"), color_malicious(result.get("file_name", "N/A"))])
    table.add_row([colored("File Type", "cyan"), color_malicious(result.get("file_type", "N/A"))]) # added
    table.add_row([colored("SHA256", "cyan"), color_malicious(result.get("sha256", "N/A"))])
    table.add_row([colored("Sub-verdict", "cyan"), color_malicious(result.get("sub_verdict", "N/A"))])
    table.add_row([colored("Verdict", "cyan"), color_malicious(result.get("verdict", "N/A"))])
    table.add_row([colored("Scan Duration", "cyan"), color_malicious(result.get("scan_duration", "N/A"))]) # added
    table.add_row([colored("Threat Name", "cyan"), color_malicious(result.get("threat_name", "N/A"))]) # added

    print(table)

def analyze_file(file_path, headers, pbar=None):
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(f'{INTEZER_API_URL}/analyze', headers=headers, files=files)
        response.raise_for_status()
        json_response = response.json()
        analysis_id = json_response['result_url'].split('/')[-1]

    def get_analysis_status():
        response = requests.get(f'{INTEZER_API_URL}/analyses/{analysis_id}', headers=headers)
        response.raise_for_status()
        return response.json()['status']

    while (status := get_analysis_status()) in ['in_progress', 'queued']:
        time.sleep(10)

    if pbar is not None:
        pbar.update(1)

    if status == 'succeeded':
        print(f'Analysis completed successfully for file: {file_path}')
        response = requests.get(f'{INTEZER_API_URL}/analyses/{analysis_id}', headers=headers)
        response.raise_for_status()
        results = response.json()
        return results
    else:
        print(f'Analysis failed for file: {file_path} with status: {status}')
        return None

parser = argparse.ArgumentParser(description='Scan a file or a directory using Intezer Analyze API.')
parser.add_argument('-f', '--file', metavar='FILE', type=str, help='The file to scan.')
parser.add_argument('-d', '--directory', metavar='DIRECTORY', type=str, help='The directory to scan.')
args = parser.parse_args()

response = requests.post(f'{INTEZER_API_URL}/get-access-token', json={'api_key': API_KEY})
response.raise_for_status()
access_token = response.json()['result']
headers = {'Authorization': f'Bearer {access_token}'}

if args.file:
    file_path = args.file
    if not os.path.exists(file_path):
        print(f'File not found: {file_path}')
        exit(1)

    if os.path.isfile(file_path):
        print(f'Starting analysis for file: {file_path}')
        results = analyze_file(file_path, headers)
        if results is not None:
            display_results(results)
    else:
        print(f'File is a directory. Use -d option to scan directories.')
elif args.directory:
    directory_path = args.directory
    if not os.path.exists(directory_path):
        print(f'Directory not found: {directory_path}')
        exit(1)

    if os.path.isdir(directory_path):
        files_to_scan = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                files_to_scan.append(file_path)

        print(f'Starting analysis for {len(files_to_scan)} files in directory: {directory_path}')
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            with tqdm(total=len(files_to_scan)) as pbar:
                for file_path in files_to_scan:
                    future = executor.submit(analyze_file, file_path, headers, pbar)
                    futures.append(future)

            for future in as_completed(futures):
                results = future.result()
                if results is not None:
                    display_results(results)
    else:
        print(f'File is not a directory. Use -f option to scan files.')
else:
    parser.print_help()

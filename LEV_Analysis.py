import argparse
import csv
import logging
import requests
from datetime import datetime, timedelta

# Constants
APP_DATE_FORMAT = "%Y-%m-%d"
EPSS_RELEVANCE_WINDOW_DAYS = 30
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"

# Global state
total_api_calls = 0
csv_writer = None
csv_file = None


def fetch_epss_score(cve_id, date_str):
    global total_api_calls
    total_api_calls += 1
    url = f"{EPSS_BASE_URL}?cve={cve_id}&date={date_str}"

    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"API request failed: {response.status_code} {response.text}")

    data = response.json().get("data", [])
    if not data:
        return 0.0

    return float(data[0]["epss"])


def weight_function(di, dn):
    delta_days = (dn.date() - di.date()).days
    return 1.0 if 0 <= delta_days < EPSS_RELEVANCE_WINDOW_DAYS else 0.0


def calculate_and_record_lev(cve_id, d0_str, dn_str, date_increment_days):
    global csv_writer
    logging.info(f"Processing CVE: {cve_id} (d0: {d0_str}, dn: {dn_str})")
    record = {
        "CVE_ID": cve_id,
        "D0": d0_str,
        "Dn": dn_str,
        "LEV_Score": 0.0,
        "Days_Scanned_In_Interval": 0,
        "API_Calls_For_CVE": 0,
        "Processing_Error_Messages": "",
    }

    try:
        d0 = datetime.strptime(d0_str, APP_DATE_FORMAT)
        dn = datetime.strptime(dn_str, APP_DATE_FORMAT)
    except ValueError as e:
        record["Processing_Error_Messages"] = str(e)
        write_record(record)
        return

    if d0 > dn:
        record["Processing_Error_Messages"] = f"d0 {d0_str} is after dn {dn_str}"
        write_record(record)
        return

    product_of_terms = 1.0
    current_date = d0
    days_scanned = 0
    initial_api_calls = total_api_calls

    while current_date <= dn:
        days_scanned += 1
        date_str = current_date.strftime(APP_DATE_FORMAT)
        try:
            epss_score = fetch_epss_score(cve_id, date_str)
        except Exception as e:
            logging.warning(f"Failed to fetch EPSS for {cve_id} on {date_str}: {e}")
            epss_score = 0.0
            record["Processing_Error_Messages"] += f"{date_str}: {str(e)}; "

        weight = weight_function(current_date, dn)
        product_of_terms *= (1.0 - epss_score * weight)
        current_date += timedelta(days=date_increment_days)

    lev_score = 1.0 - product_of_terms
    record["LEV_Score"] = round(lev_score, 6)
    record["Days_Scanned_In_Interval"] = days_scanned
    record["API_Calls_For_CVE"] = total_api_calls - initial_api_calls

    write_record(record)


def initialize_csv(output_path):
    global csv_file, csv_writer
    if output_path:
        csv_file = open(output_path, mode='w', newline='')
        csv_writer = csv.DictWriter(csv_file, fieldnames=[
            "CVE_ID", "D0", "Dn", "LEV_Score",
            "Days_Scanned_In_Interval", "API_Calls_For_CVE",
            "Processing_Error_Messages"
        ])
        csv_writer.writeheader()


def write_record(record):
    if csv_writer:
        csv_writer.writerow(record)


def close_csv():
    if csv_file:
        csv_file.close()


def main():
    parser = argparse.ArgumentParser(description="LEV Score Calculator using EPSS API")
    parser.add_argument("-cves", required=True, help="Comma-separated CVE list")
    parser.add_argument("-d0", help="Start date (YYYY-MM-DD)")
    parser.add_argument("-dn", help="End date (YYYY-MM-DD), defaults to today")
    parser.add_argument("-o", help="CSV output file path")
    parser.add_argument("-w", type=int, default=1, help="Date increment (default: 1)")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="LEVCalc: %(asctime)s - %(message)s")

    dn_str = args.dn or datetime.utcnow().strftime(APP_DATE_FORMAT)
    try:
        dn = datetime.strptime(dn_str, APP_DATE_FORMAT)
    except ValueError:
        logging.error(f"Invalid dn format: {dn_str}")
        return

    if args.d0:
        d0_str = args.d0
    else:
        d0_str = (dn - timedelta(days=90)).strftime(APP_DATE_FORMAT)
        logging.info(f"-d0 not provided; defaulting to {d0_str}")

    initialize_csv(args.o)

    cve_ids = [c.strip() for c in args.cves.split(",") if c.strip()]
    logging.info(f"Starting LEV calculations for {len(cve_ids)} CVEs")

    for cve_id in cve_ids:
        calculate_and_record_lev(cve_id, d0_str, dn_str, args.w)

    close_csv()
    logging.info(f"Finished processing. Total API calls: {total_api_calls}")


if __name__ == "__main__":
    main()
import re
from datetime import datetime
import math

"""
Takes parsed lines and creates key, value pairs based on the three analyses that will be performed.
"""


def map(lines):
    dict_overall = {}
    for i in range(len(lines)):
        dict_overall[lines[i][0], lines[i][1], lines[i][4]] = lines[i]
    return dict_overall


"""
Takes a raw input line and separates all values based on regular expressions.
Error handling is implemented via regex returning None values if a line does not meet the format.
"""


def parse(log_line):
    pattern = r'^(\S+) \[(.*?)\] (\S+) (\S+) (\d{3}) (\d+)$'
    match = re.match(pattern, log_line.strip())
    if match:
        try:
            date = match.group(2)
            modified_date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            print("Value error")
            return None

        return [
            match.group(1),
            modified_date,  # Configure datetime
            match.group(3),
            match.group(4),
            match.group(5),
            match.group(6),
        ]
    else:
        return None


"""
Takes a mapped dictionary of key, value pairs and performs analysis on the data via reduction.
IP's are marked as suspicious if they attempt to access '/admin' or '/config'.
IPs are also marked as suspicious if they attempt to access 401 or 403 more than ten times.
"""


def reduce(map_dict):
    sus_list = ["/admin", "/config"]

    # IP ANALYSIS --------------------------------------------------
    ip_analysis_dict = {}
    for ip_entry in map_dict:
        # Doesn't exist
        if ip_analysis_dict.get(ip_entry[0]) is None:
            ip_analysis_dict[ip_entry[0]] = {
                'num_instances': 0,
                'num_success': 0,
                'count_401': 0,
                'count_403': 0,
                'is_sus': False
            }

        # Doesn't exist
        num_instances = ip_analysis_dict[ip_entry[0]]['num_instances']
        num_instances += 1

        num_success = ip_analysis_dict[ip_entry[0]]['num_success']
        if (ip_entry[2][0] == '2'):
            num_success += 1

        count_401 = ip_analysis_dict[ip_entry[0]]['count_401']
        if (ip_entry[2] == '401'):
            count_401 += 1

        count_403 = ip_analysis_dict[ip_entry[0]]['count_403']
        if (ip_entry[2] == '403'):
            count_403 += 1

        # Is suspicious if attempting to access /admin or /config
        is_sus = ip_analysis_dict[ip_entry[0]]['is_sus']
        is_sus = (map_dict[ip_entry][-3] in sus_list) or is_sus
        # Request is suspicious if the number of 401s are greater than 10
        if (ip_analysis_dict[ip_entry[0]]['count_401'] > 10):
            is_sus = True
        # Request is suspicious if the number of 403s are greater than 10
        if (ip_analysis_dict[ip_entry[0]]['count_403'] > 10):
            is_sus = True

        ip_analysis_dict[ip_entry[0]] = {
            'num_instances': num_instances,
            'num_success': num_success,
            'count_401': count_401,
            'count_403': count_403,
            'is_sus': is_sus
        }

    # TIME WINDOW ANALYSIS --------------------------------------------------
    # time_window_dict[start_hour, end_hour] : total_req
    # to see if already in, check if hour extracted from datetime, n+1 is in dict
    time_window_dict = {datetime(2000, 1, 1, hour).strftime(
        '%H:00'): 0 for hour in range(24)}
    for entry in map_dict:

        # if time entry does not exist
        key = entry[1].strftime('%H:00')
        time_window_dict[key] += 1

    # ERROR PATTERN ANALYTICS --------------------------------------------------
    error_analysis_dict = {}
    for error_type in map_dict:
        # Skip 2xx's
        if error_type[2][0] == '2':
            continue

        # Doesn't exist
        if error_analysis_dict.get(error_type[2]) is None:
            error_analysis_dict[error_type[2]] = {
                "num_instances": 0,
                "url_frequency": {}
            }

        num_instances = error_analysis_dict[error_type[2]]['num_instances']
        num_instances += 1

        # URL doesnt exist
        frequency_dict = error_analysis_dict[error_type[2]
                                             ]['url_frequency']

        if frequency_dict.get(map_dict[error_type][-3]) is None:
            frequency_dict[map_dict[error_type][-3]] = 0

        frequency_dict[map_dict[error_type][-3]] += 1

        error_analysis_dict[error_type[2]] = {
            'num_instances': num_instances,
            'url_frequency': frequency_dict
        }

    return [ip_analysis_dict, time_window_dict, error_analysis_dict]


"""
A driver function for the MapReduce file.
Opens a file in the same directory called 'updated_network.log' and calls the parser on the raw data.
The parsed data is then mapped, creating a dictionary of key,value pairs
The mapped key,values are then reduced, and their output data (in the form of dictionaries) are printed.
"""


def driver():
    log_file = './updated_network.log'
    with open(log_file, 'r') as file:
        log_lines = file.readlines()

    # Parse all lines and store it for mapping functions
    parsed_lines = []
    for line in log_lines:
        parsed_line = parse(line)
        if parsed_line is not None:
            parsed_lines.append(parsed_line)

    map_dict = map(parsed_lines)
    [reduced_ips, reduced_times, reduced_requests] = reduce(map_dict)

    # IP Analysis
    print("--- IP Analysis ---")
    for reduced_ip in reduced_ips:
        percent_success = (
            reduced_ips[reduced_ip]['num_success'] / reduced_ips[reduced_ip]['num_instances']) * 100
        percent_success = math.floor(percent_success)

        ip_str = f"{reduced_ip}: {reduced_ips[reduced_ip]['num_instances']} requests ({
            percent_success}% success)"
        if (reduced_ips[reduced_ip]['is_sus']):
            ip_str += " [SUSPICIOUS]"

        print(ip_str)

    # Time Window Analysis
    hours_dict = {
        "00:00": "01:00",
        "01:00": "02:00",
        "02:00": "03:00",
        "03:00": "04:00",
        "04:00": "05:00",
        "05:00": "06:00",
        "06:00": "07:00",
        "07:00": "08:00",
        "08:00": "09:00",
        "09:00": "10:00",
        "10:00": "11:00",
        "11:00": "12:00",
        "12:00": "13:00",
        "13:00": "14:00",
        "14:00": "15:00",
        "15:00": "16:00",
        "16:00": "17:00",
        "17:00": "18:00",
        "18:00": "19:00",
        "19:00": "20:00",
        "20:00": "21:00",
        "21:00": "22:00",
        "22:00": "23:00",
        "23:00": "00:00",
    }
    peak = 0
    peak_time = ""
    for reduced_time in reduced_times:
        if reduced_times[reduced_time] > peak:
            peak = reduced_times[reduced_time]
            peak_time = reduced_time

    print("\n--- Hourly Analysis ---")
    for reduced_time in reduced_times:
        time_str = f"{
            reduced_time}-{hours_dict[reduced_time]}: {reduced_times[reduced_time]} requests"
        if reduced_time == peak_time:
            time_str += " (peak)"
        print(time_str)

    # Error Request Analysis
    print("\n--- Error Analysis ---")
    for error_request in reduced_requests:
        # Get the top url
        top_url_dict = {"top_url": "", 'top_frequency': -1}
        for url in reduced_requests[error_request]['url_frequency']:
            if reduced_requests[error_request]['url_frequency'][url] > top_url_dict['top_frequency']:
                top_url_dict["top_url"] = url
                top_url_dict["top_frequency"] = reduced_requests[error_request]['url_frequency'][url]

        print(f"{error_request}: {
              reduced_requests[error_request]['num_instances']} occurrences (top URL: {top_url_dict["top_url"]})")


if __name__ == "__main__":
    driver()

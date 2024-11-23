from datetime import datetime, timedelta
import math


def map(lines):
    dict_overall = {}
    for i in range(len(lines)):
        dict_overall[lines[i][0], lines[i][1], lines[i][4]] = lines[i]
    return dict_overall


def parse(log_line):
    log_arr = log_line.split(' ')
    log_arr[1] = datetime.strptime(
        log_arr[1][1:-1], "%Y-%m-%dT%H:%M:%S")  # Configure datetime
    log_arr[-1] = log_arr[-1].strip()  # Remove newline
    return log_arr


def reduce(map_dict):
    sus_list = ["/admin", "/config"]

    # IP ANALYSIS
    ip_analysis_dict = {}
    for ip_entry in map_dict:
        # num_instances
        # num_success
        # count_401
        # count_403
        # is_sus

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
    
    # TIME WINDOW ANALYSIS
    # time_window_dict[start_hour, end_hour] : total_req
    # to see if already in, check if hour extracted from datetime, n+1 is in dict
    time_window_dict = {datetime(2000, 1, 1, hour).strftime('%I:00 %p'): 0 for hour in range(24)}
    for entry in map_dict:

        #if time entry does not exist
        key = entry[1].strftime('%I:00 %p')
        time_window_dict[key] += 1
    
    return [ip_analysis_dict, time_window_dict, {}]


def driver():
    log_file = './updated_network.log'
    with open(log_file, 'r') as file:
        log_lines = file.readlines()

    # Parse all lines and store it for mapping functions
    parsed_lines = []
    for line in log_lines:
        parsed_lines.append(parse(line))

    map_dict = map(parsed_lines)
    reduced_ips = {}
    reduced_times = {}
    reduced_requests = {}
    [reduced_ips, reduced_times, reduced_request] = reduce(map_dict)

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
    hours_dict = { "12:00 AM": "01:00 AM", "01:00 AM": "02:00 AM", "02:00 AM": "03:00 AM", "03:00 AM": "04:00 AM", "04:00 AM": "05:00 AM", "05:00 AM": "06:00 AM", "06:00 AM": "07:00 AM", "07:00 AM": "08:00 AM", "08:00 AM": "09:00 AM", "09:00 AM": "10:00 AM", "10:00 AM": "11:00 AM", "11:00 AM": "12:00 PM", "12:00 PM": "01:00 PM", "01:00 PM": "02:00 PM", "02:00 PM": "03:00 PM", "03:00 PM": "04:00 PM", "04:00 PM": "05:00 PM", "05:00 PM": "06:00 PM", "06:00 PM": "07:00 PM", "07:00 PM": "08:00 PM", "08:00 PM": "09:00 PM", "09:00 PM": "10:00 PM", "10:00 PM": "11:00 PM", "11:00 PM": "12:00 AM" }
    peak = 0
    peak_time = ""
    for reduced_time in reduced_times:
        if reduced_times[reduced_time] > peak:
            peak = reduced_times[reduced_time]
            peak_time = reduced_time

    print("--- Hourly Analysis ---")
    for reduced_time in reduced_times:
        time_str = f"{reduced_time}-{hours_dict[reduced_time]}: {reduced_times[reduced_time]}"
        if reduced_time == peak_time:
            time_str += " (peak)"
        print(time_str)

if __name__ == "__main__":
    driver()

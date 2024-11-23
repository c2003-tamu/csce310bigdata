from datetime import datetime
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

    return [ip_analysis_dict, {}, {}]


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


if __name__ == "__main__":
    driver()

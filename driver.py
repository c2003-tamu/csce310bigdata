from datetime import datetime


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
    return_list = []

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

        is_sus = ip_analysis_dict[ip_entry[0]]['is_sus']
        is_sus = (map_dict[ip_entry][-3] in sus_list) or is_sus

        if ((map_dict[ip_entry][-3] in sus_list)):
            print(f"\t{map_dict[ip_entry][-3]} is {(map_dict[ip_entry]
                  [-3] in sus_list)} makes {ip_entry[0]} sus")

        ip_analysis_dict[ip_entry[0]] = {
            'num_instances': num_instances,
            'num_success': num_success,
            'count_401': count_401,
            'count_403': count_403,
            'is_sus': is_sus
        }

    return [ip_analysis_dict, False]


def driver():
    log_file = './updated_network.log'
    with open(log_file, 'r') as file:
        log_lines = file.readlines()

    # Parse all lines and store it for mapping functions
    parsed_lines = []
    for line in log_lines:
        parsed_lines.append(parse(line))

    map_dict = map(parsed_lines)
    return_list = reduce(map_dict)

    for entry in return_list[0]:
        print(f"{entry} : {return_list[0][entry]}\n")


if __name__ == "__main__":
    driver()

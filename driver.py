from datetime import datetime


def parse(log_line):
    log_arr = log_line.split(' ')
    log_arr[1] = datetime.strptime(
        log_arr[1][1:-1], "%Y-%m-%dT%H:%M:%S")  # Configure datetime
    log_arr[-1] = log_arr[-1].strip()  # Remove newline
    return log_arr


def driver():
    log_file = './updated_network.log'
    with open(log_file, 'r') as file:
        log_lines = file.readlines()

    # Parse all lines and store it for mapping functions
    parsed_lines = []
    for line in log_lines:
        parsed_lines.append(parse(line))

    print(parsed_lines)


if __name__ == "__main__":
    driver()

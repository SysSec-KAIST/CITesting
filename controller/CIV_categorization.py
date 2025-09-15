import os
import argparse
import pandas as pd
import logging
from colorlog import ColoredFormatter
from pprint import pprint

logger = logging.getLogger("")
logger.setLevel(logging.DEBUG)
# debug, info, warning, error, critical


def __log_setting():
    # Global Setting
    formatter = ColoredFormatter(
        '[%(asctime)s]>> %(log_color)s[%(levelname)s] > %(message)s',
        reset=True,
        log_colors={
            'DEBUG':    'cyan',
            'INFO':     'white,bold',
            'INFOV':    'cyan,bold',
            'WARNING':  'yellow',
            'ERROR':    'red,bold',
            'CRITICAL': 'red,bg_white',
        }
    )

    # Console Print
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # File Save
    file_handler = logging.FileHandler("./civ_categorization.log", 'w')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


ie_cols = ["Column 3", "Column 4", "Column 5", "Column 6", "Column 7", "Column 8", "Column 9", "Column 10", "Column 11"]

group_cols = []

test_cols = ["Column 13", "Column 22"]

ie_dict = {}
civ_group = {}

# Global variables
depth = "depth0"
state = "DEREGI"


def depth_parser(filename):
    global depth
    global state
    depth = filename.split('/')[-1].split('_')[1]
    state = filename.split('/')[-1].split('_')[2]
    logger.debug("Depth: {}".format(depth))
    logger.debug("State: {}".format(state))


def make_ie_list(df, col):
    ie_list = pd.unique(df[col]).tolist()
    logger.debug("{} :: {}".format(col, ie_list))

    return ie_list


def remove_invalid(df):
    resp_i = int(group_cols[1].split(' ')[1]) - 1
    req_i = resp_i - 3

    req_col = 'Column {}'.format(req_i)
    resp_col = 'Column {}'.format(resp_i)

    logger.debug('Before len: {}'.format(len(df)))

    valid_rows = []
    for idx, row in df.iterrows():
        try:
            req_text = str(row[req_col]).split(']')[-1].strip().split(' ')[0]
            resp_text = str(row[resp_col]).split('>')[-1].strip().split(' ')[0]
            if req_text == resp_text:
                valid_rows.append(idx)
        except (IndexError, AttributeError):
            logger.error("IndexError or AttributeError occurred at index {}".format(idx))
            continue
    df = df.loc[valid_rows].reset_index(drop=True)

    logger.debug('After len: {}'.format(len(df)))
    return(df)

def group_result(df):
    grouped = df.groupby(group_cols)
    i = 0
    total = 0
    for key, df in grouped:
        logger.debug("Group Key: {}".format(key))
        logger.debug(df.head())
        logger.debug("Count: {}".format(len(df)))
        logger.debug("-" * 50)
        total += len(df)
        i += 1

    logger.debug("Total Groups: {}".format(i))
    logger.debug("Total Count: {}".format(total))

    return grouped
    

def get_group_by_index(grouped, index):
    # grouped = df.groupby(group_cols)
    groups = list(grouped)
    
    if index < len(groups):  # check index
        key, group_data = groups[index]  
        logger.debug("Group Key: {}".format(key))
        logger.debug(group_data.head())
        logger.debug("Count: {}".format(len(group_data)))
    else:
        logger.debug("Index '{}' is out of range.".format(index))
    
    return key, group_data

def analyze_one_group(df, key, dict_index=0):
    logger.debug("*" * 50)
    logger.debug("Analyze One Group")

    unique_ie = []
    for col in ie_cols:
        ie_uniq = df[col].unique()
        logger.debug("{} \t:: {}".format(col, ie_uniq))
        full_ie = ie_dict[col]
        logger.debug("Full IE  \t:: {}".format(full_ie))

        if set(ie_uniq) == set(full_ie):
            logger.debug("All IE\n")
        else:
            logger.debug("Specific IE\n")
            unique_ie.append(ie_uniq.tolist())

    dict_key = (depth, dict_index)
    next_procedure = [key[1]]
    oracle = [key[2:-1]]


    civ_group[dict_key] = [
        len(df),
        unique_ie,
        next_procedure,
        oracle
    ]


# Main function to analyze CSV file
def analyze_csv(csv_file):
    df = pd.read_csv(csv_file)
    df = df.fillna("EMPTY")
    logger.debug(df['Column 4'].head())
    
    for i in range(int(depth[-1])):
        ie_cols.append('Column {}'.format(15 + (i*4)))

    group_cols.append('Column {}'.format(12 + (int(depth[-1])*4)))

    cnt = int(depth[-1]) * 4
    ref_index = 13 + cnt
    group_cols.append('Column {}'.format(ref_index))
    actual_columns = len(df.columns)
    for i in range(1, 15):
        col_index = ref_index + 2 + i
        if col_index <= actual_columns:
            group_cols.append('Column {}'.format(col_index))
        else:
            break

    if depth[-1] != '0':
        df = remove_invalid(df)
    
    for col in ie_cols:
        tmp_ie_list = make_ie_list(df, col)
        ie_dict[col] = tmp_ie_list

    grouped = group_result(df)

    for i in range(0, len(grouped)):
        logger.debug("*" * 50)
        one_key, one_df = get_group_by_index(grouped, i)
        analyze_one_group(one_df, one_key, i)

    logger.debug("*" * 50)
    pprint(civ_group)


if __name__ == "__main__":
    __log_setting()

    # argument checking
    argparser = argparse.ArgumentParser(epilog="CAUTION: -f/--file or -d/--dir is required")
    argparser.add_argument("-f", "--file", help="log file name", default="no_name")
    argparser.add_argument("-d", "--dir", help="directory name for enhanced analysis", default="no_name")

    args = argparser.parse_args() 
    # argument error hanlding
    if args.file == "no_name" and args.dir == "no_name":
        logger.error("-f/--file or -d/--dir is required")
        exit()

    # Start main code
    if args.dir != "no_name":
        dirname = args.dir
        logger.info("Directory Name: {}".format(dirname))
        files = os.listdir(dirname)

        logger.info("Files Count: {}".format(len(files)))
        logger.error("Not yet implemented")
        exit()
    elif args.file != "no_name":
        filename = args.file
        logger.info("File Name: {}".format(filename))
        depth_parser(filename)
        analyze_csv(filename)
        exit()

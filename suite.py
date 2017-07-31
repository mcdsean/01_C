import os, re, zipfile, operator

import py_common

FVDL_NAME = "audit.fvdl"
# todo: this will need to be firmly defined
SCORE_THRESHOLD_UNWEIGHTED = 0.45
SCORE_THRESHOLD_WEIGHTED = 0.45
LANG = 'c'


class TestCase(object):
    # def __init__(self, filename):
    def __init__(self, test_case_name, tc_type, true_false):
        # test case name
        self.test_case_name = test_case_name
        # juliet or kdm
        self.tc_type = tc_type
        # true or false
        self.true_false = true_false

        ''' runtime attributes '''
        # FILE NAME, LINE, FUNCTION
        self.hit_data = []
        '''
         Level     FILE NAME   LINE     COLOR
           2           x         x      Blue  
           1           x                Yellow
           0                            White (Unique)
        '''
        # todo: for coloring, need to develop. currently works as is but needs to be more efficient
        self.hit_data_match_levels = {}

        # enclosing function of hit
        self.opp_names = []
        # juliet/false only, else = 1
        self.opp_counts = 0
        # opps found
        self.score = 0
        # percent of opps found
        self.percent = 0

        ''' auto-run methods on creation '''
        self.get_juliet_false_opp_counts_per_test_case(self.test_case_name)
        # self.update_match_levels(self.TODO)

    def get_juliet_false_opp_counts_per_test_case(self, test_case_name):

        # this method only applies to juliet/false test cases
        if self.tc_type == 'juliet' and self.true_false == 'FALSE':

            test_case_dir = os.path.join(os.getcwd(), 'juliet', test_case_name.rsplit('/', 1)[0])

            # walk thru the test case dir associated with this test case and look for the file(s) in this test case
            for root, dirs, files in os.walk(test_case_dir):
                for file in files:
                    opp_count = 0
                    # get file(s) associated with this test case and find opps
                    # if file.startswith(test_case_name.rsplit('/', 1)[1]) and file.endswith('.c'):
                    # if file.startswith(test_case_name.rsplit('/', 1)[1]) and file.endswith(LANG):
                    # todo: 06/14/17 need to test this with the c test cases
                    if LANG == 'c':
                        if file.startswith(test_case_name.rsplit('/', 1)[1]) and file.endswith(LANG):
                            # read thru the entire test case file and look for 'good...()' function calls (i.e. opportunities)
                            with open(root + "\\" + file, 'r') as inF:
                                for line in inF:
                                    # todo: 6/14/17 for c++, we have multiple good()'s
                                    # if 'good...()' in line:
                                    if line.lstrip().startswith('good') and line.rstrip().endswith('();') \
                                            and 'Source' not in line and 'Sink' not in line:
                                        opp_count += 1
                                        self.opp_counts = opp_count
                                        self.opp_names.append(line.strip()[:-3])
                            ''' 
                            stop searching the files associated wtih this test case since the opp info has been 
                            found and it only occurs in one file 
                            '''
                            if opp_count != 0:
                                # pad for even display
                                self.opp_names = self.opp_names + [''] * (4 - len(self.opp_names))
                                break
                    elif LANG == 'cpp':
                        # get the single file in this test case that contains the opp counts
                        if file.startswith(test_case_name.rsplit('/', 1)[1]) and file.endswith(LANG) \
                                and '_bad' not in file and '_goodG2B' not in file and '_goodB2G' not in file:

                            # read thru the entire test case file and look for 'good...()' function calls (i.e. opportunities)
                            with open(root + "\\" + file, 'r') as inF:
                                line_content = []
                                for line in inF:
                                    # todo: 6/14/17 for c++, we have multiple good()'s
                                    # if 'good...()' in line:
                                    if line.lstrip().startswith('good') and line.rstrip().endswith('();') \
                                            and 'Source' not in line and 'Sink' not in line and 'good()' not in line:
                                        line_content.append(line)
                                        opp_count += 1
                                        self.opp_counts = opp_count
                                        self.opp_names.append(line.strip()[:-3])
                            ''' 
                            stop searching the files associated wtih this test case since the opp info has been 
                            found and it only occurs in one file 
                            '''
                            print('FILE_WITH_OPP*****', file, 'OPP_COUNT*****', opp_count)
                            if opp_count != 0:
                                # pad for even display
                                self.opp_names = self.opp_names + [''] * (4 - len(self.opp_names))
                                break

        else:
            self.opp_counts = 1
            self.opp_names.extend(['N/A', '', '', ''])

    def update_match_levels(self, file_name):
        # todo: calculate the match level
        self.hit_data_match_levels = {file_name: 1}


class Xml(object):
    def __init__(self, cwe_id_padded, cwe_num, tc_type, true_false, tc_lang, new_xml_name, scan_data_file):
        self.cwe_id_padded = cwe_id_padded
        self.cwe_num = cwe_num
        self.tc_type = tc_type
        self.true_false = true_false
        self.tc_lang = tc_lang
        self.new_xml_name = new_xml_name
        self.scan_data_file = scan_data_file

        ''' runtime attributes '''
        self.tc_count = 0
        self.num_of_hits = 0
        self.percent_hits = 0
        self.tc_path = ''
        self.acceptable_weakness_ids = []
        self.acceptable_weakness_ids_dict = {}
        self.used_wids = []
        # list of test case objects
        self.test_cases = []

        print('PROJECT FILE---', self.scan_data_file)


class Suite(object):
    def __init__(self, source_path, dest_path, tool_name):
        self.source_path = source_path
        self.dest_path = dest_path
        self.tool_name = tool_name

        # raw files produced by scanner
        self.scan_data_files = []
        # list of xml project objects
        self.xml_projects = []
        # list of tc paths
        self.tc_paths = []

        ''' runtime attributes '''
        # stores the hits per test case {test_case_name: hit_count}
        self.suite_hit_data = {}
        self.suite_hit_data_complete = []
        self.name_space = ''
        self.tag_info = []
        self.acceptable_weakness_ids_full_list = []
        self.acceptable_weakness_ids_full_list_dict = {}
        self.used_wids_per_cwe = []
        self.used_wids_per_cwe_dict = {}
        self.weightings_per_cwe_dict = {}
        self.unique_cwes = []
        # totals
        self.suite_tc_count_true = 0
        self.suite_tc_count_false = 0
        self.suite_tp_count = 0
        self.suite_fp_count = 0
        self.suite_cwe_count = 0

        # precision, unweighted
        self.precision_values_per_cwe_unweighted = {}
        self.precision_accumulated_valid_values_unweighted = 0
        self.precision_accumulated_valid_count_unweighted = 0  # excluding 'N/A'
        self.precision_average_unweighted = 0
        self.precision_score_unweighted = 0
        # precision, weighted
        self.precision_values_per_cwe_weighted = {}
        self.precision_accumulated_valid_values_weighted = 0
        self.precision_accumulated_valid_count_weighted = 0  # excluding 'N/A'
        self.precision_average_weighted = 0
        self.precision_score_weighted = 0
        # recall, unweighted
        self.recall_values_per_cwe_unweighted = {}
        self.recall_accumulated_values_unweighted = 0
        self.recall_accumulated_count_unweighted = 0
        self.recall_average_unweighted = 0
        self.recall_score_unweighted = 0
        # recall, weighted
        self.recall_values_per_cwe_weighted = {}
        self.recall_accumulated_values_weighted = 0
        self.recall_accumulated_count_weighted = 0
        self.recall_average_weighted = 0
        self.recall_score_weighted = 0

        # accumulated results, unweighted
        self.overall_score_unweighted = 0
        self.overall_required_threshold_unweighted = SCORE_THRESHOLD_UNWEIGHTED
        # accumulated results, weighted
        self.overall_score_weighted = 0
        self.overall_required_threshold_weighted = SCORE_THRESHOLD_UNWEIGHTED

        # todo 5/11/7 default these to 'FAIL' and ' .... does require manual review
        self.manual_review_recommendataion = ' * There are no test cases requiring manual review!'
        self.pass_fail = 'PASS'

        self.duplicate_file_name_hits = set()

        self.clear_totals()
        ''' auto-run methods on creation '''
        self.create_xml_dir()
        # get the xml info and create copies
        self.get_xml_info(self.scan_data_files)
        # get the test case counts
        self.get_test_case_paths_and_counts(self.scan_data_files)
        # sort
        self.sort_by_columns()

    def clear_totals(self):
        self.suite_tc_count_true = 0
        self.suite_tc_count_false = 0
        self.suite_tp_count = 0
        self.suite_fp_count = 0

    def create_xml_dir(self):
        # create, or empty, 'xmls' folder
        #
        # Note: Deleting entire folder and then re-creating it immediately sometimes conflicts
        # with anti-virus sortware and cannot always release handles quick enough, so the entire
        # parent folder is not deleted, only the files withing it. This prevents this problem
        #
        if not os.path.exists(self.dest_path):
            py_common.print_with_timestamp("The path \"" + self.dest_path + "\" does not exist")
            py_common.print_with_timestamp("creating directory \"" + self.dest_path + "\"")
            os.makedirs(self.dest_path)
        else:
            py_common.print_with_timestamp(self.dest_path + " already exists. Cleaning before use...")
            fileList = os.listdir(self.dest_path)
            for fileName in fileList:
                # os.remove(self.dest_path + "//" + fileName)
                os.remove(os.path.join(self.dest_path, fileName))

        # fortify files are not in standard xml format
        if self.tool_name == 'fortify':
            self.scan_data_files = py_common.find_files_in_dir(self.source_path, '.*?\.fpr$')
        else:
            self.scan_data_files = py_common.find_files_in_dir(self.source_path, '.*?\.xml$')

    def get_xml_info(self, scan_data_files):

        for scan_data_file in scan_data_files:

            # get cwe number from project name
            match = re.search('CWE\d+', scan_data_file)
            cwe_num = match.group(0)[3:].lstrip('0')

            # get test case language
            tc_lang = scan_data_file.rsplit('.', 4)[1].rsplit('_', 1)[1].lower()

            # get true or false
            if '\\T\\' in scan_data_file:
                true_false = 'TRUE'
            elif '\\F\\' in scan_data_file:
                true_false = 'FALSE'
            else:
                true_false = 'N/A'

            # create xml name from scan data file name
            base_name = os.path.basename(scan_data_file)

            # get test case type
            if 'juliet' in scan_data_file:
                tc_type = 'juliet'
                # suffix = '_' + true_false[:1] + '_' + 'juliet'
                new_xml_name = str(base_name.rsplit('.', 2)[1]) + '_' + true_false[:1] + '_' + 'juliet' + '.xml'
            elif 'kdm' in scan_data_file:
                tc_type = 'kdm'
                new_xml_name = re.sub('(_[TF]_)', '_', str(base_name.rsplit('.', 2)[1])) + '_' + true_false[
                                                                                                 :1] + '_' + 'kdm' + '.xml'
            else:
                tc_type = 'N/A'
                new_xml_name = 'N/A'

            self.copy_xml_file(scan_data_file, new_xml_name)

            cwe_id_padded = 'CWE' + cwe_num.zfill(3)

            self.xml_projects.append(
                Xml(cwe_id_padded, cwe_num, tc_type, true_false, tc_lang, new_xml_name, scan_data_file))

        return self.xml_projects

    def copy_xml_file(self, scan_data_file, new_xml_name):

        if self.tool_name == 'fortify':
            # self.extract_fvdl_from_fpr(scan_data_file, self.dest_path)

            # fortify .fpr files need unzipped to get the xml
            myzip = zipfile.ZipFile(scan_data_file, mode='r')
            myzip.extract(FVDL_NAME, path=self.dest_path)
            myzip.close()

        # format xml name
        tool_path_to_xml = os.path.join(self.dest_path, FVDL_NAME)
        new_path_to_xml = os.path.join(self.dest_path, new_xml_name)
        # create fresh xml name
        os.rename(tool_path_to_xml, new_path_to_xml)

    def get_test_case_paths_and_counts(self, scan_data_files):

        key_list = []
        root_list = []

        tc_types = ['juliet', 'kdm']

        # get the lowest level, non-empty, paths for juliet and kdm
        for tc_type in tc_types:
            for root, dirs, files in os.walk(os.path.join(os.getcwd(), tc_type)):
                if files and not dirs:
                    root_list.append(root)

        for i, xml_project in enumerate(scan_data_files):
            del key_list[:]

            # get the xml name for each project and use it's contents to grab the tc dir
            xml_name = getattr(self.xml_projects[i], 'new_xml_name')[:-4]

            key_list = xml_name.split('_')
            if 'kdm' in xml_name and 'CWE123' in key_list[0]:
                key_list[0] = 'CWE123a'  # account for kdm 123a naming anomaly
            key_list[0] = key_list[0] + '_'  # guard against confusion 'CWE78_' and 'CWE789_'

            for root in root_list:
                if all(x in root for x in key_list):
                    # print('TC PATH FOUND----------', root)
                    tc_path = root.replace(os.getcwd(), '')[1:]
                    setattr(self.xml_projects[i], 'tc_path', tc_path)
                    project_id = i
                    self.count_test_cases(project_id, tc_path)
                    # root_list.remove(root) #todo: this was intended to speed up searches but left some fields blank in the spreadsheet (delete or troubleshoot)
                    break

    def count_test_cases(self, projedt_id, tc_path):
        test_case_files = []

        tc_type = getattr(self.xml_projects[projedt_id], 'tc_type')
        tc_lang = getattr(self.xml_projects[projedt_id], 'tc_lang')
        for root, dirs, files in os.walk(tc_path):

            for file in files:
                if file.endswith(tc_lang) and 'CWE' in file:
                    if tc_type == 'juliet':
                        print('JULIET TEST CASE FILE', file)
                        # reduce filename to test case name by removing variant and file extension
                        # file = re.sub('[a-z]?\.\w+$', '', file)
                        #todo 06/08/17 test this in the 'c' version and update it if it works
                        file = re.sub('([a-z]?\.\w+$)|(_good.*$)|(_bad.*$)', '', file)
                        test_case_files.append(file)
                    elif tc_type == 'kdm':
                        # if not file.endswith(".h") and not file.endswith("_a.c") and not file.endswith(".obj") and file.startswith("SFP"):
                        if not file.endswith(".h") and not file.endswith("_a." + LANG) and not file.endswith(
                                ".obj") and file.startswith("SFP"):
                            test_case_files.append(file)
                            print('KDM TEST CASE FILE', file)
                    else:
                        print('Not a KDM or Juliet Test Case File.')

        tc_count = len(set(test_case_files))
        setattr(self.xml_projects[projedt_id], 'tc_count', tc_count)

    # def import_weakness_ids(self, scan_data_files):
    #     cwe_weakness_ids = []
    #
    #     ws = wb['Weakness IDs']
    #
    #     # get weakness ids from duplicated vendor sheet
    #     for row_idx in ws.iter_rows():
    #         for cell in row_idx:
    #             if str(cell.value) == cwe.lstrip('0'):
    #                 for cell in row_idx:
    #                     cwe_weakness_ids.append(cell.value)
    #
    #                 return cwe_weakness_ids


    def sort_by_columns(self):

        # reverse the order of the desired sort priority #todo: consider moving this to another location
        self.xml_projects.sort(key=operator.attrgetter('true_false'), reverse=False)
        self.xml_projects.sort(key=operator.attrgetter('tc_type'))
        self.xml_projects.sort(key=operator.attrgetter('cwe_id_padded'))

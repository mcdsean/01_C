# ! /usr/bin/env/python 3.0
#
# Defines how to run an analysis with Fortify for C/C++.
#
# 2017-02-09 jspielvogel@keywcorp.com added comments, TODOs, and refactored so the script is less tool-specific so that we can use this as a baseline for other tools' scripts
# 2013-06-07 jspielvogel@keywcorp.com modified to use argparse to parse the input; added more command line options; use the -h option for help on using this script 
# 2013-04-24 smcdonagh@keywcorp.com reviewed and added comments
# 2013-01-07 rhsteve@nsa.gov: updated scan command to analyze code with modifications to the properties file for deeper tracing of indirect function calls
# 2012-12-18 jspielvogel@keywcorp.com make use of the java heap size specified in py_common, use the new syntax when calling py_common.run_analysis()
# 2012-06-27 jspielvogel@keywcorp.com make use of py_common.create_or_clean_directory(), clean up code
# 2012-05-02 jspielvogel@keywcorp.com: added new run_analysis command to scan split directories, specify output path for .fprs, use py_common.print_with_timestamp
# 2011-12-01 pmkulin@nsa.gov: Fixed typo in -Xmx switch.
# 2011-11-30 pmkulin@nsa.gov: Increase Java heap size and enable Fortify's 64-bit mode, to avoid out-of-memory errors.
# 2011-11-23 pmkulin@nsa.gov: Added -clean step to delete intermediate files after each run, to keep from filling C: with temporary files
# 2011-11-17 pmkulin@nsa.gov: Added -verbose, -debug, -logfile, and -Xmx flags to match Java version of the script.  Increased memory to 1.6GB to (hopefully) avoid out-of-memory errors.
# 2010-08-04 john.laliberte@mandiant.com: run the fortify commands
# 2010-08-02 john.laliberte@mandiant.com: initial version

import sys, os, argparse

# add parent directory to search path so we can use py_common
sys.path.append("..")

import py_common

TOOL_NAME = "HP Fortify"

# Globals that capture arguments passed in at the command line
output_path = ""
project_prefix = ""
suite_path = ""

# Recommended by Fortify to increase these parameters from default value of 128 and 34.  If the
# logfile reports 'Data Flow Analyzer did not follow some virtual or indirect functions...', 
# continue to double these values until warnings do not occur in the scan results.  May also 
# require additional memory allocation.
MAX_INDIRECT_RESOLUTIONS_FOR_CALL = "256"
MAX_FUN_PTRS_FOR_CALL = "136"

# MAIN_TOOL_COMMAND is the common command and options used for this tool's analysis
MAIN_TOOL_COMMAND = "sourceanalyzer"
MAIN_TOOL_COMMAND += " " + "-verbose"  # Output more verbose error messages
MAIN_TOOL_COMMAND += " " + "-debug"  # Output Fortify debug info
MAIN_TOOL_COMMAND += " " + "-Xmx" + py_common.get_tool_study_max_java_heap_size()
MAIN_TOOL_COMMAND += " " + "-64"  # Remove this line if working on 32-bit platform

"""
	TODO
	
	Move this to a common script (i.e. py_common)
"""


def get_build_name(bat_file):
    return bat_file[:-4]


def run_fortify_c_cpp(bat_file):
    """
    Build and analyze the source code using the batch file.
    """

    # build_name is based upon the name of the batch file
    build_name = get_build_name(bat_file)

    build_id = TOOL_NAME.replace(" ", "_")  # Replace any spaces in the tool name with underscore
    build_id += "." + project_prefix
    build_id += "." + py_common.get_timestamp()
    build_id += "." + build_name

    # Create file names and paths - we do this here so that the commands
    # generated below can remain unchanged as long as there are no new options
    # being passed to Fortify
    build_log_filename = build_id + "-build-log.txt"
    scan_log_filename = build_id + "-scan-log.txt"
    clean_log_filename = build_id + "-clean-log.txt"
    fpr_file = os.path.join(output_path, build_id) + ".fpr"

    # Build the command to compile the code
    command = MAIN_TOOL_COMMAND
    command += " " + "-b" + " " + build_id
    command += " " + "-logfile" + " " + build_log_filename
    command += " " + "touchless"
    command += " " + bat_file

    py_common.print_with_timestamp("Running " + command)
    py_common.run_commands([command])

    # Build the command to analyze the code
    command = MAIN_TOOL_COMMAND
    command += " " + "-b" + " " + build_id
    command += " " + "-logfile" + " " + scan_log_filename
    command += " " + "-scan"
    command += " " + "-f" + " \"" + fpr_file + "\""
    command += " " + "-Dcom.fortify.sca.limiters.MaxIndirectResolutionsForCall=" + MAX_INDIRECT_RESOLUTIONS_FOR_CALL
    command += " " + "-Dcom.fortify.sca.limiters.MaxFunPtrsForCall=" + MAX_FUN_PTRS_FOR_CALL

    py_common.print_with_timestamp("Running " + command)
    py_common.run_commands([command])

    # Perform a clean so that we don't fill up the HD
    command = MAIN_TOOL_COMMAND
    command += " " + "-b" + " " + build_id
    command += " " + "-logfile" + " " + clean_log_filename
    command += " " + "-clean"

    py_common.print_with_timestamp("Running " + command)
    py_common.run_commands([command])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A script used to run ' + TOOL_NAME + ' (C/C++) on various suites.')

    parser.add_argument('suite_path',
                        help='The input path to the test case suite to scan (i.e. juliet\\T, juliet\\F, kdm\\T, kdm\\F')
    parser.add_argument('output_path', help='path to the output directory (where the tool results will be saved)')
    parser.add_argument('project', help='The name of the project (no spaces) (Suite_01_C)')

    args = parser.parse_args()

    suite_path = args.suite_path
    output_path = args.output_path
    project_prefix = args.project

    # Use full path to output path - this is important as the run_analysis function
    # would use the relative path in the test case directory
    output_path = os.path.abspath(output_path)

    py_common.create_or_clean_directory(output_path)

    # Analyze the test cases
    py_common.run_analysis(suite_path, "CWE.*\.bat", run_fortify_c_cpp)

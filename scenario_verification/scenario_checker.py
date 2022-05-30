import argparse
import logging
import sys
import os
import logging
import time
from shutil import which

# Get an instance of a logger
logger = logging.getLogger(__name__)

def is_tool(name):
    return which(name) != None

def dump_properties(of, pfname):
    of.write("\n")
    with open(pfname, "r") as f:
        spec = False
        for line in f:
            if line[0] == "#":
                continue
            if "INVARSPEC" in line or "LTLSPEC" in line or "CTLSPEC" in line or "JUSTICE" in line:
                spec = True
            if spec:
                of.write(line)
            if spec and line.strip() == "":
                spec = False

def generate_lists(sdir, prop):
    scenarios = ["{}/{}".format(sdir, f) for f in os.listdir("{}".format(sdir)) if ".smv" in f and not ".swp" in f]
    properties = []

    if prop != "all":
        properties.append(prop)
    else:
        lst = [d for d in os.listdir("properties") if os.path.isdir("properties/{}".format(d))]
        logging.debug(lst)
        for d in lst:
            if "property.smv" in os.listdir("properties/{}".format(d)):
                properties.append("properties/{}/property.smv".format(d))

    logging.debug("# of Scenarios: {}".format(len(scenarios))) 
    logging.debug("Properties: {}".format(properties))

    return scenarios, properties

def evaluate_tmp_file(rfname):
    with open(rfname, "a") as rf:
        with open("tmp.txt", "r") as f:
            for line in f:
                line = line.strip()

                if "***" in line:
                    continue

                if len(line) == 0:
                    continue

                if "no counterexample" in line:
                    continue

                if "as demonstrated" in line:
                    continue

                if "Trace " in line:
                    continue

                if "specification" in line:
                    rf.write("\n")
                rf.write("{}\n".format(line))

def run(scenarios=[], properties=[], ofdir=None, rfname="result.log", mlen=30):
    with open(rfname, "w") as rf:
        rf.write("Result of Scenario Checker\n")

    for sname in sorted(scenarios):
        num = int(sname.split(".")[0].split("_")[-1])
        logging.info(">>>>> Verifying Scenario #{} <<<<<".format(num))
        if ofdir == None:
            ofname = "tmp.smv"
        else:
            ofname = "{}/check_{}.smv".format(ofdir, num)

        with open(sname, "r") as f:
            with open(rfname, "a") as rf:
                rf.write("\n>> Scenario #{}\n".format(num))
            with open(ofname, "w") as of:
                for line in f:
                    of.write(line)

                for pfname in properties:
                    dump_properties(of, pfname)

        os.system("nuXmv -bmc -bmc_length {} {}".format(mlen, ofname))
        #os.system("nuXmv -bmc -bmc_length {} {} >> tmp.txt".format(mlen, ofname))
        #evaluate_tmp_file(rfname)

    if os.path.exists("tmp.smv"):
        os.remove("tmp.smv")

    if os.path.exists("tmp.txt"):
        os.remove("tmp.txt")

def command_line_args():
    global parser
    parser = argparse.ArgumentParser(description="""Scenario Checker""")

    parser.add_argument("-s", "--scenario-directory", metavar="<directory of scenarios>", help="Directory of Scenarios", type=str, default="scenarios")
    parser.add_argument("-p", "--property", metavar="<property file>", help="Property file path (all/[file path])", type=str, default="all")
    parser.add_argument('-l', "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL>", help="Log level", default="INFO")
    parser.add_argument('-d', "--output-directory", metavar="<output directory>", help="Output directory")
    parser.add_argument('-o', "--output", help="Whether to output the property-inserted scenarios", action='store_true', default=False)
    parser.add_argument('-r', "--result", metavar="<result file path>", help="Result file path", type=str, default="result.log")
    parser.add_argument("-m", "--max-length", metavar="<maximum length for bounded model checking>", help="Maximum length of bounded model checking", type=int, default=30)

    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    if not os.path.exists(args.scenario_directory):
        logging.error("Directory of scenarios: {} does not exist".format(args.scenario_directory))
        parser.print_help()
        sys.exit(1)

    if args.property != "all" and not os.path.exists(args.property):
        logging.error("Property file: {} does not exist".format(args.property))
        parser.print_help()
        sys.exit(1)

    if args.output == True:
        if args.output_directory == None:
            logging.error("Output directory should be inserted")
            parser.print_help()
            sys.exit(1)

        if not os.path.exists(args.output_directory):
            os.mkdir(args.output_directory)
   
    if not is_tool("nuXmv"):
        logging.error("Please install the nuXmv model checker")
        sys.exit(1)

    logging.basicConfig(level=args.log)

    scenarios, properties = generate_lists(args.scenario_directory, args.property)
    run(scenarios=scenarios, properties=properties, ofdir=args.output_directory, rfname=args.result, mlen=args.max_length)

if __name__ == "__main__":
    main()

import argparse
import logging
import sys
import io
import os
import itertools as IT
import xml.etree.ElementTree as ET
import logging
from scenario_generator import *
PY2 = sys.version_info[0] == 2
StringIO = io.BytesIO if PY2 else io.StringIO

# Get an instance of a logger
logger = logging.getLogger(__name__)

def find_contendition_transitions(fsm):
    transition_contendingTransition_map = []
    for i in range(len(fsm.transitions)):
        transition = fsm.transitions[i]
        contendingTransitions = []
        for j in range(len(fsm.transitions)):
            if (i==j):
                continue
            if(fsm.transitions[i].start == fsm.transitions[j].start):
                contendingTransitions.append(fsm.transitions[j].transition_label)
        transition_contendingTransition_map.append((transition, contendingTransitions))
    return transition_contendingTransition_map

def sort_variables(variables):
    varnames = []
    independent_variables = []
    dependent_variables = []

    if len(variables) == 0:
        return [] 

    for var in variables:
        varnames.append(var.varname)

    for var in variables:
        possible_values = var.possible_values
        independence = True
        if possible_values:
            for p in possible_values:
                if p in varnames:
                    independence = False

        if independence:
            independent_variables.append(var)
        else:
            dependent_variables.append(var)
    
    ret = independent_variables + sort_variables(dependent_variables)

    return ret

# dump vars
def dump_variables(of, variables):
    of.write('\nVAR\n\n')
    of.write('\n------------------- Environment and State variables --------------------\n')
    variables = sort_variables(variables)
    for var in variables:
        if(var.datatype == 'boolean'):
            of.write(var.varname +  '\t:\t' + var.datatype + ';\t\n')
        elif (var.datatype == 'enumerate'):
            of.write(var.varname + '\t:\t{')
            for i in range(len(var.possible_values)):
                if(i == len(var.possible_values) -1 ):
                    of.write(var.possible_values[i])
                else:
                    of.write(var.possible_values[i] + ', ')
            of.write('};\t\n')

# dump sequence numbers
def dump_numbers(of, nums):
    of.write('\n----------------- Numbers -------------------\n')

    for num in nums:
        of.write(num.name +  '\t:\t' + str(num.start) + '..' + str(num.end) + '\t;\n')

# dumping states of a FSM
def dump_states(of, fsms):
    for fsm in fsms:
        of.write('\n---------------- state for ' + fsm.fsm_label + ' state machine ----------------\n')
        of.write('\n' + str(fsm.fsm_label).lower() + '_state\t:\n')
        of.write('{\n')
        for i in range(len(fsm.states)):
            if (i < len(fsm.states) - 1):
                of.write(str('\t' + fsm.states[i]) + ',\n')
            else:
                of.write('\t'+str(fsm.states[i]) + '\n')
        of.write('};\n')

# get the unique action_names of a fsm
def get_unique_action_names(fsm):
    action_labels = []
    for transition in fsm.transitions:
        for action in transition.actions:
            if action.action_label not in action_labels:
                action_labels.append(action.action_label)
    return action_labels


# dump fsm_actions
def dump_actions(of, fsms):
    for fsm in fsms:
        of.write('------------ Possible ' + fsm.fsm_label + ' actions ----------------\n')
        action_labels = get_unique_action_names(fsm)
        fsm_label_entity= fsm.fsm_label.lower().split('_')[0].strip()
        logging.debug (fsm_label_entity)
        of.write('\n'+ fsm.fsm_label.lower() + '_action\t:\n')
        of.write('{\n')
        if len(action_labels) > 0:
            of.write('\tnull_action,\n')
        else:
            of.write('\tnull_action\n')

        for i in range(len(action_labels)):
            if (i < len(action_labels) - 1):
                of.write('\t' + action_labels[i] + ',\n')
            else:
                of.write('\t' + action_labels[i] + '\n')
        of.write('};\n')

# dump transitions of the FSMs
def dump_transitions(file, fsms):
    # dumping actions
    for fsm in fsms:
        file.write('\n-----------------' + fsm.fsm_label +' transitions --------------------\n')
        transition_contendingTransitions_map = find_contendition_transitions(fsm)
        for i in range(len(fsm.transitions)):
            condition = fsm.transitions[i].condition
            file.write(fsm.transitions[i].transition_label +'\t:=\t (' + fsm.fsm_label.lower()+ '_state = ' +
                       fsm.transitions[i].start + ' & '+ condition + ')\t;\n')
    return

def dump_manual(input_file, file, section_name):
    # create element tree object
    tree = ET.parse(input_file)

    # get root element
    root = tree.getroot()

    manual_dumps = root.find('manual_dump')
    if (root.find('manual_dump')):
        for instance in manual_dumps:
            section = instance.find('section').text
            section = str(section).strip().upper()
            if (section in str(section_name).upper()):
                text = instance.find('text').text
                lines = str(text).split('\n')
                for line in lines:
                    file.write(line.lstrip() + '\n')
    return

def dump_manual_checks(of, manual_checks):
    of.write("\n")
    for check in manual_checks:
        of.write(check + ';\n')
    return

def dump_defines(file, fsms, manual_checks):
    file.write('\n\nDEFINE\n')
    dump_transitions(file, fsms)
    dump_manual_checks(file, manual_checks)
    return


# get the mapping (fsm, (deststate, transitions))
# for each deststate of a FSM, find the transitions
# transitions are list of transition_labels
def get_fsm_deststate_transition_map(fsms):
    fsm_deststate_transition_map = []
    for fsm in fsms:
        deststate_transition_map = []
        for state in fsm.states:
            transitions = []
            for transition in fsm.transitions:
                if (str(state).lower().strip() == str(transition.end).lower().strip()):
                    transitions.append(transition.transition_label)
            deststate_transition_map.append((state, transitions))
        fsm_deststate_transition_map.append((fsm, deststate_transition_map))

    return fsm_deststate_transition_map


# dump FSM transition state machines
def dump_state_machines(file, fsms):
    fsm_deststate_transition_map = get_fsm_deststate_transition_map(fsms)
    for i in range(len(fsm_deststate_transition_map)):
        fsm = fsm_deststate_transition_map[i][0]
        file.write('\n\n---------------' + fsm.fsm_label + ' state machine ------------------\n')
        deststate_transition_map = fsm_deststate_transition_map[i][1]
        file.write("\ninit(" + fsm.fsm_label.lower() +'_state)\t:=' +
                       fsm.init_state.lower() + ';\n')
        file.write("\nnext(" + fsm.fsm_label.lower() + '_state)\t:=\t case\n\n')
        for j in range(len(deststate_transition_map)):
            deststate = deststate_transition_map[j][0]
            transition_labels = deststate_transition_map[j][1]
            if (len(transition_labels) != 0):
                file.write('(')
            for k in range(len(transition_labels)):
                if(k < len(transition_labels)-1):
                    file.write(transition_labels[k] + ' | ')
                else:
                    file.write(transition_labels[k])
            if(len(transition_labels) != 0):
                file.write(' )\t:\t' + deststate.lower() +'\t;\n')
        file.write('TRUE\t:\t' + fsm_deststate_transition_map[i][0].fsm_label.lower() +'_state\t;\n')
        file.write('esac\t;')

# get the mapping (fsm, (action, transitions))
# for each action of a FSM, find the corresponding transitions
def get_fsm_action_transition_map(fsms):
    fsm_action_transition_map = []
    for fsm in fsms:
        action_transition_map = []
        action_labels = get_unique_action_names(fsm)
        for action_label in action_labels:
            transitions = []
            for transition in fsm.transitions:
                for action in transition.actions:
                    if (action_label.lower() == action.action_label.lower()):
                        transitions.append(transition.transition_label)
            action_transition_map.append((action_label, transitions))
        fsm_action_transition_map.append((fsm, action_transition_map))
    return fsm_action_transition_map

def dump_action_state_machines(of, fsms):
    fsm_action_transition_map = get_fsm_action_transition_map(fsms)
    for i in range(len(fsm_action_transition_map)):
        action_transition_map = fsm_action_transition_map[i][1]
        if len(action_transition_map) > 1:
            of.write("\n\n\ninit(" + fsm_action_transition_map[i][0].fsm_label.lower() + '_action)\t:= null_action\t;\n')
            of.write("\nnext(" + fsm_action_transition_map[i][0].fsm_label.lower() + '_action)\t:=\t case\n\n')
            for j in range(len(action_transition_map)):
                of.write('(')
                action_label = action_transition_map[j][0]
                transition_labels = action_transition_map[j][1]
                for k in range(len(transition_labels)):
                    if(k < len(transition_labels)-1):
                        of.write(transition_labels[k] + ' | ')
                    else:
                        of.write(transition_labels[k])
                fsm_label_entity = fsm_action_transition_map[i][0].fsm_label.lower().split('_')[0].strip()
                of.write(' )\t:\t' + action_label + '\t;\n')

            of.write('TRUE\t:\t null_action\t;\n')
            of.write('esac\t;')

def dump_state_variable_state_machines(file, variables, fsms):
    var_value_transition_map = []
    file.write('\n\n--------------- State Variables state machine ------------------\n')
    for var in variables:
        if (var.controltype.strip() in 'state'):
            state_variable = var.varname
            value_transition_map = []
            for possible_value in var.possible_values:
                transitions = []
                for fsm in fsms:
                    for transition in fsm.transitions:
                        for action in transition.actions:
                            state_variable = action.action_label.split('=')[0]
                            if(state_variable.strip() in var.varname):
                                value = action.action_label.split('=')[1]
                                if(possible_value == value.strip()):
                                    transitions.append(transition)
                if (len(transitions)>0):
                    value_transition_map.append((possible_value, transitions))

            if(len(value_transition_map) > 0):
                var_value_transition_map.append((var, value_transition_map))

    logging.debug ("--------- dump --------")
    for i in range(len(var_value_transition_map)):
        var = var_value_transition_map[i][0]
        state_variable = var.varname
        value_transition_map = var_value_transition_map[i][1]

        if(var.datatype == 'boolean'):
            file.write("\n\n\ninit(" + state_variable + ')\t:= ' + var.initial_value.upper() + '\t;\n') # TRUE and FALSE in uppercase
        elif(var.datatype == 'enumerate'):
            file.write("\n\n\ninit(" + state_variable + ')\t:= ' + var.initial_value + '\t;\n')

        file.write("\nnext(" + state_variable + ')\t:=\t case\n')
        for j in range(len(value_transition_map)):
            val = value_transition_map[j][0]
            transitions = value_transition_map[j][1]
            file.write('(')
            for k in range(len(transitions)):
                if(k == len(transitions)-1):
                    file.write(transitions[k].transition_label)
                else:
                    file.write(transitions[k].transition_label + ' | ')
            file.write(' )\t:\t' + val + '\t;\n')
        file.write('TRUE\t:\t' +  var.varname+ '\t;\n')
        file.write('esac\t;\n')

    return

def dump_num_state_machines(of, nums, fsms):
    num_value_transition_map = []
    for num in nums:
        name = num.name
        value_transition_map = []
        for possible_value in num.possible_values:
            possible_value = possible_value.lstrip()
            logging.debug ('possible_value = {}'.format(possible_value))
            transitions = []
            for fsm in fsms:
                for transition in fsm.transitions:
                    for action in transition.actions:
                        sname = str(action.action_label.split('=')[0]).strip()

                        if (name.strip() == sname):
                            logging.debug ('sname = {}'.format(sname))
                            next_value = str(action.action_label.split('=')[1]).strip()
                            entity_prefix = fsm.fsm_label.split("_")[0].lower()
                            if next_value == "uip" or next_value == "eip" or next_value == "dip":
                                logging.debug("{}> (before) sname: {}, value: {}".format(fsm.fsm_label, sname, action.action_label))

                                action.action_label = action.action_label.replace(next_value, "{}_{}".format(entity_prefix, next_value))
                                logging.debug("{}> (after) sname: {}, value: {}".format(fsm.fsm_label, sname, action.action_label))

                            if next_value == "target_addr" or next_value == "target_port":
                                logging.debug("{}> (before) sname: {}, value: {}".format(fsm.fsm_label, sname, action.action_label))
                                action.action_label = action.action_label.replace(next_value, "{}_{}".format(entity_prefix, next_value))
                                logging.debug("{}> (after) sname: {}, value: {}, next_value: {} ({})".format(fsm.fsm_label, sname, action.action_label, next_value, possible_value))

                            if next_value == "rcvd_src_addr" or next_value == "rcvd_src_port":
                                logging.debug("{}> (before) sname: {}, value: {}".format(fsm.fsm_label, sname, action.action_label))
                                action.action_label = action.action_label.replace(next_value, "{}_{}".format(entity_prefix, next_value))
                                logging.debug("{}> (after) sname: {}, value: {}, next_value: {} ({})".format(fsm.fsm_label, sname, action.action_label, next_value, possible_value))

                            if (possible_value == next_value.strip()):
                                logging.debug ('possible_value matched')
                                transitions.append(transition)
            if (len(transitions) > 0):
                value_transition_map.append((possible_value, transitions))

        if (len(value_transition_map) > 0):
            num_value_transition_map.append((num, value_transition_map))


    logging.debug ("--------- dump --------")
    of.write('\n\n')
    for i in range(len(nums)):
        of.write('init(' + nums[i].name + ')\t:= ' + nums[i].start + '\t;\n')

    for i in range(len(num_value_transition_map)):
        name = num_value_transition_map[i][0].name
        value_transition_map = num_value_transition_map[i][1]
        of.write('\nTRANS\n')
        of.write('case\n')
        for j in range(len(value_transition_map)):
            val = value_transition_map[j][0]
            transitions = value_transition_map[j][1]
            of.write('(')
            for k in range(len(transitions)):
                if (k == len(transitions) - 1):
                    of.write(transitions[k].transition_label)
                else:
                    of.write(transitions[k].transition_label + ' | ')
            of.write(' )\t:\tnext(' + name + ')\t=\t' +  val + '\t;\n')

        of.write('TRUE\t:\tnext(' + name + ')\t=\t' + name +'\t;\n')
        of.write('esac\t;\n')

def dump_assigns(of, variables, nums, fsms):
    of.write('\n\nASSIGN\n\n')
    dump_state_machines(of, fsms)
    #dump_action_state_machines(of, fsms)
    dump_state_variable_state_machines(of, variables, fsms)
    dump_num_state_machines(of, nums, fsms)

def create_vars_combined(variable):
    variables = []
    for k in variable:
        variables += variable[k][3]

    var_unique = []
    var_unique.append(variables[0])

    for v1 in variables:
        flag = 0
        for v2 in var_unique:
            if v1.varname in v2.varname:
                flag = 1
                break
        if flag == 0:
            var_unique.append(v1)

    return var_unique

def create_nums_combined(num):
    nums = []
    for k in num:
        nums += num[k][4]
    nums = add_common_numbers(nums)
    return nums

def create_fsms_combined (fsm):
    fsms = []
    for k in fsm:
        fsms.append(fsm[k][5])
    return fsms

def compile_manual_checks_combined(check):
    checks = []

    for k in check:
        if check[k][6] is not None and len(check[k][6]) != 0:
            for c in check[k][6]:
                checks.append(c)

    checks = add_common_manual_checks(checks)

    return checks

def threat_instrumentation(config, scenarios):
    ret = scenarios
    channel_fsms = {}
    keys = ["Adversary UE-to-Others", "Adversary ePDG-to-Others", "Adversary DNS-to-Others"]
    lst = []

    for key in keys:
        if key in config:
            lst.append(config[key])
            
    for c in lst:
        fsm_label = c.split("/")[1].split(".")[0].upper()
        channel_fsms[fsm_label] = parseDOT(c, fsm_label)

    for idx in ret:
        for c in channel_fsms:
            ret[idx][c] = channel_fsms[c]
    
    return ret

def main_combined(config=None, ofprefix=None, ofdir=None):

    logging.debug("Entity Types: {}".format(config["Entity Types"]))
    logging.debug("Initial FSMs Directory: {}".format(config["Initial FSMs Directory"]))

    entity_types = config["Entity Types"]
    context_types = config["Context Types"]

    initial_fsms_dir = config["Initial FSMs Directory"]
    initial_fsms_lst = ["{}/{}".format(initial_fsms_dir, f) for f in os.listdir(initial_fsms_dir) if ".dot" in f and not f.startswith(".") and not ".bak" in f]
    logging.debug("Initial FSMs List: {}".format(initial_fsms_lst))
    initial_fsms = {}

    for m in initial_fsms_lst:
        fsm_label = m.split("/")[1].split(".")[0].upper()
        logging.debug("FSM label: {}".format(fsm_label))
        logging.debug("FSM file:{}".format(m))
        initial_fsms[fsm_label] = parseDOT(m, fsm_label) 

    constraints_for_entity = prepare_constraints_for_entities(config, entity_types)
    constraints_for_context = prepare_constraints_for_contexts(config, context_types)

    logging.debug("Constraints for entity: {}".format(constraints_for_entity))
    logging.debug("Constraints for context: {}".format(constraints_for_context))
    model_variants = generate_model_variants(initial_fsms)
    logging.info(">>>>> # of model variants <<<<<")
    for label in model_variants:
        logging.info("  {}: {}".format(label, len(model_variants[label])))
    logging.info(">>>>>>>>>>>>>><<<<<<<<<<<<<<<<<")
    protocol_stacks = generate_protocol_stacks_per_entity(model_variants, entity_types, constraints_for_entity)
    logging.info(">>>>> # of protocol stacks per entity <<<<<")
    for entity in protocol_stacks:
        logging.info("  {}: {}".format(entity, len(protocol_stacks[entity])))
    logging.info(">>>>>>>>>>>>>><<<<<<<<<<<<<<<<<")
    init_num, final_num, scenarios = generate_scenarios(protocol_stacks, entity_types, constraints_for_context)
    logging.info(">>>>> # of scenarios <<<<<")
    logging.info("  # of initial scenarios: {}".format(init_num))
    logging.info("  # of final scenarios: {}".format(final_num))
    logging.info("  cut-off rate: {}".format(round((init_num - final_num)/init_num, 2)))
    logging.info(">>>>>>>>>>>>>><<<<<<<<<<<<<<<<<")
    threat_instrumented_scenarios = threat_instrumentation(config, scenarios)

    # return (env_vars, state_vars, num_vars, smv_vars, smv_nums, fsm, smv_manual_checks)

    #for i in threat_instrumented_scenarios:
    for i in range(1):
        variables = create_vars_combined(threat_instrumented_scenarios[i])
        nums = create_nums_combined(threat_instrumented_scenarios[i]) # smv_vars
        fsms = create_fsms_combined(threat_instrumented_scenarios[i])

        manual_checks = compile_manual_checks_combined(threat_instrumented_scenarios[i])
        logging.debug ('manual_checks = {}'.format(manual_checks))
        prefix, extension = ofprefix.split(".")
        ofname = "{}/{}_{}.{}".format(ofdir, prefix, i, extension)

        f = open(ofname, "w")
        f.write("MODULE main\n")
        dump_variables(f, variables)
        dump_numbers(f, nums)
        dump_states(f, fsms)

        dump_defines(f, fsms, manual_checks)
        dump_assigns(f, variables, nums, fsms)

        f.close()

def parse_config(cname):
    ret = {}

    with open(cname, "r") as f:
        for line in f:
            if line[0] == "#":
                continue

            if line.strip() == "":
                continue

            line = line.split("#")[0].strip()

            key, val = line.strip().split(": ")

            if "Entity Types" in key:
                val = val.strip().split(", ")

            if "Context Types" in key:
                val = val.strip().split(", ")

            if "Directory" in key:
                if not os.path.exists(val):
                    logging.error("{} directory ({}) does not exist".format(key, val))
                    sys.exit(1)

            if "Constraints" in key:
                if not os.path.exists(val):
                    logging.error("{} file ({}) does not exist".format(key, val))
                    sys.exit(1)

            if "Adversary" in key:
                if not os.path.exists(val):
                    logging.error("{} file ({}) does not exist".format(key, val))
                    sys.exit(1)

            ret[key] = val

    return ret

def command_line_args():
    global parser
    parser = argparse.ArgumentParser(description="""DOT to SMV translator.""")

    parser.add_argument("-c", "--conf", metavar="<configuration file>", help="Configuration file", type=str, default="vowifi.conf")
    parser.add_argument('-l', "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL>", help="Log level", default="INFO")
    parser.add_argument('-d', "--directory", metavar="<output directory>", help="Output directory", default="../scenario_verification/scenarios")
    parser.add_argument('-o', "--output", metavar="<output file anme>", help="Output file name", default="scenario.smv")

    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    if not os.path.exists(args.conf):
        logging.error("Configuration file: {} does not exist".format(args.conf))
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.directory):
        os.mkdir(args.directory)
   
    conf = parse_config(args.conf)
    logging.basicConfig(level=args.log)

    main_combined(config=conf, ofprefix=args.output, ofdir=args.directory)

if __name__ == "__main__":
    main()

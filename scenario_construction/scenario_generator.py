import copy
import logging

VAR_INDEX = 3
NUM_INDEX = 4
FSM_INDEX = 5
MANUAL_INDEX = 6

class Variable(object):
    def __init__(self, varname, datatype, controltype, initial_value, possible_values, fsm):
        self.varname = varname
        self.datatype = datatype
        self.controltype = controltype
        self.initial_value = initial_value
        self.possible_values = possible_values
        self.fsm = fsm

    def set_varname(self, varname):
        self.varname = varname

    def set_datatype(self, datatype='boolean'):
        self.datatype = datatype

    def set_controltype(self, controltype='environment'):
        self.controltype = controltype

    def set_initial_value(self, initial_value):
        self.initial_value = initial_value

    def set_possible_values(self, possible_values):
        self.possible_values = possible_values

class Number(object):
    def __init__(self, name, start, end, possible_values):
        self.name = name
        self.start = start
        self.end = end
        self.possible_values = possible_values

    def set_numname(self, numname):
        self.name = numname

    def set_possible_values(self, possible_values):
        self.possible_values = possible_values

class Action(object):
    def __init__(self, action_label):
        self.action_label = action_label

    def set_action_label(self, action_label):
        self.action_label = action_label

class Transition(object):
    def __init__(self, transition_label, start, end, condition, actions):
        self.transition_label = transition_label
        self.start = start
        self.end = end
        self.condition = condition
        self.actions = actions
        self.contending_transitions = []

    def set_condition(self, condition):
        self.condition = condition

    def set_actions(self, actions):
        self.actions = actions

    def set_contending_transitions(self, contending_transitions):
        self.contending_transitions = contending_transitions

class FSM(object):
    def __init__(self, fsm_label, states, init_state, transitions):
        self.fsm_label = fsm_label
        self.states = states
        self.init_state = init_state
        self.transitions = transitions

    def set_states(self,states):
        states = []
        for state in states:
            self.states.append(state)

    def add_state(self,state):
        self.states.append(state)

    def set_actions(self, actions):
        self.actions = []
        for action in actions:
            self.actions.append(action)

    def add_action(self, action):
        self.actions.append(action)

def filewrite(fw,transition_label,start_state,end_state,condition,actions):
    fw.write("label: " + str(transition_label) + "\n" + "start_state: " + str(
        start_state) + "\n" + "end state: " + str(end_state) + "\n" + "condition: " + str(
        condition) + "\n")
    fw.write("actions: " + "\n")
    for action in actions:
        fw.write(str(action.action_label) + "\n")
    fw.write("\n")

def parseDOT(dotfile, fsm_label):
    #fw = open(fsm_label+".txt", "w+")

    # store the parsing results
    smv_vars = []
    smv_nums = []
    smv_transitions = []
    smv_manual_checks = []

    system_fsms = []
    system_channels = []
    injective_adversaries = []

    fsm_states = []
    env_vars = []
    state_vars = []
    num_vars = []
    transitions = []
    transition_counter = 0

    logging.debug("\n\ndot file: {}\n\n".format(dotfile))
    with open(dotfile, "r") as f:
        for line in f:
            if 'node' in line:
                strg = line.split(']')[1].split(';')[0].strip()
                fsm_states.append(strg.strip())
                logging.debug ('state = {}'.format(strg.strip()))
                logging.debug ("fsm_states: {}".format(fsm_states))

            elif 'initial_state' in line:
                init_state = line.split(':')[1].strip()
                logging.debug ('init state = {}'.format(init_state))

            elif 'environment variables' in line:
                strg = line.split(':')[1].split(';')
                for s in strg:
                    s = s.strip()
                    if s is None or s == '':
                            break
                    env_var = s.strip()
                    env_vars.append(env_var)
                    new_var = Variable(env_var, 'boolean', 'environment', None, None, fsm_label)
                    smv_vars.append(new_var)
                    logging.debug ('env_var = {}'.format(env_var))

            elif 'state variables' in line:
                vars = line.split(':')[1].split(';')
                for v in vars:
                    v = v.strip()
                    if v is None or v == '':
                        break

                    state_tokens = v.strip()

                    strg = state_tokens.split('{')

                    state_var_label = strg[0].strip() # strg[1]: true, false}<false>
                    state_vars.append(state_var_label)

                    values = strg[1].split('}')

                    possible_values = []
                    strg = values[0].split(',') # values[1]:<false>
                    for s in strg:
                        if 'true' in s.strip().lower():
                            possible_values.append('TRUE')
                        elif 'false' in s.strip().lower():
                            possible_values.append('FALSE')
                        else:
                            possible_values.append(s.strip())
                    logging.debug ('possible_values = {}'.format(possible_values))
                    init_value = values[1].split('<')
                    init_value = init_value[1].split('>')[0].strip()
                    if 'TRUE' in possible_values:
                        if 'true' in init_value.lower():
                            init_value = 'TRUE'
                        elif 'false' in init_value.lower():
                            init_value = 'FALSE'
                        logging.debug ('init value = {}'.format(init_value))
                        new_var = Variable(state_var_label, 'boolean', 'state', init_value, possible_values, fsm_label)
                    else:
                        new_var = Variable(state_var_label, 'enumerate', 'state', init_value, possible_values, fsm_label)
                    smv_vars.append(new_var)

            elif 'number variables' in line:
                vars = line.split(':')[1].split(';')

                for v in vars:
                    v = v.strip()
                    if v is None or v == '':
                        break

                    num_tokens = v.strip()


                    strg = num_tokens.split('{')
                    num_var_label = strg[0].strip()  # str[1]: 0,6}<((rrc_sec_ctx + 1) mod 7), 0>
                    num_vars.append(num_var_label)


                    values = strg[1].split('}')
                    strg = values[0].split(',')  # values[1]:<((rrc_sec_ctx + 1) mod 7), 0>
                    start = strg[0]
                    end = strg[1]

                    init_values = values[1].split('<')
                    init_values = init_values[1].split('>')[0].strip()
                    init_values = init_values.split(',')
                    possible_values = []
                    for iv in init_values:
                        possible_values.append(iv.strip())

                    new_num = Number(num_var_label, start, end, possible_values)
                    smv_nums.append(new_num)

            elif 'define' in line:
                checks = line.split(":", 1)
                checks = checks[1].split(';')
                logging.debug ('checks = {}'.format(checks))
                for check in checks:
                    check = check.strip()
                    if len(check) > 0:
                        smv_manual_checks.append(check.lstrip())
                logging.debug ('smv_manual_checks = {}'.format(smv_manual_checks))

            elif '//' in line and line.startswith('//'):
                continue

            elif '->' in line:
                transition = ''
                strg = line.split('->')
                start_state = strg[0].strip()

                strg = strg[1].split('[')
                end_state = strg[0].strip()


                if start_state not in fsm_states:
                    logging.debug (line)
                    logging.error ('start_state ({}) is not in the list of states ({})'.format(start_state, fsm_states))
                    return

                if end_state not in fsm_states:
                    logging.debug ('states = {}'.format(state_vars))
                    logging.info ('end_state {}'.format(end_state))
                    logging.error ('end_state is not in the list of states')
                    return

                strg = strg[1].split('"')
                if len(strg) == 3:  #transition is written in one line
                    transition = strg[1]
                    logging.debug ("transition: {}".format(transition))

                else:
                    transition = strg[1].strip()
                    logging.debug ("transition: {}".format(transition))
                    j = i+1
                    while '"]' not in lines[j].strip():
                        transition = transition + lines[j].strip()
                        logging.debug ("transition: {}".format(transition))
                        j = j + 1
                    strg = lines[j].split('"]')
                    transition = transition + strg[0]
                    i = j
                    transitions.append(transition)

                transition_counter = transition_counter + 1
                transition_label = fsm_label + "_T" + str(transition_counter)

                values = transition.split('/')
                logging.debug ('{}> values = {}'.format(transition_label, values))

                cond_str = values[0]
                act_str = values[1]

                # PARSING ACTIONS
                acts = act_str.split(',')
                actions = []
                for act in acts:
                    action_label = act.strip()
                    if action_label == '':
                        logging.error ("There are some transitions in comments (//) or missing underscore sign or extra comma due to which empty action is happening")
                        logging.info (line)
                        continue

                    if action_label == '_':
                        action_label = 'null_action'

                        logging.debug ('action_label: {}'.format(action_label))

                    else:
                        logging.debug ('internal_action: {}'.format(action_label))

                        if '=' in action_label:
                            int_act_tokens = action_label.split('=')
                            int_act = int_act_tokens[0].strip()
                            value = int_act_tokens[1].strip().lstrip()
                            logging.debug ('value = {}'.format(value))
                            if 'true' in value:
                                action_label = action_label.replace('true', 'TRUE')
                            elif 'false' in value:
                                action_label = action_label.replace('false', 'FALSE')
                            logging.debug ('action_label = {}'.format(action_label))

                        elif '++' in action_label:
                            int_act_tokens = action_label.split('++')
                            int_act = int_act_tokens[0].strip()
                            action_label = '(' + int_act + '=' + int_act + '+ 1)'

                    if action_label != '' and action_label != None:
                        logging.debug ("action label = {}".format(action_label))
                        new_action = Action(action_label)
                        actions.append(new_action)

                # PARSING CONDITIONS
                condition = cond_str
                logging.debug ('condition = {}'.format(condition))
                
                cond_tokens = cond_str.split(' ')
                logging.debug ('condition = {}'.format(condition))

                for token in cond_tokens:
                    token = token.strip()
                    if '(' in token:
                        token = token.split('(')[1]
                    if ')' in token:
                        token = token.split(')')[0]

                logging.debug ('Modified condition: {}'.format(condition))

                new_transition = Transition(transition_label, start_state, end_state, condition, actions)
                #filewrite(fw, transition_label, start_state, end_state, condition, actions)
                smv_transitions.append(new_transition)

        fsm = FSM(fsm_label, fsm_states, init_state, smv_transitions)

        logging.debug ("")
        logging.debug (">>> {} <<<".format(fsm_label))
        logging.debug ('states = {}'.format(fsm_states))
        logging.debug ('environment variables = {}'.format(env_vars))
        logging.debug ('state vars = {}'.format(state_vars))
        logging.debug ('Transitions = ')
        for transition in smv_transitions:
            logging.debug (transition.condition)
        logging.debug ("")

    #fw.close()
    return (env_vars, state_vars, num_vars, smv_vars, smv_nums, fsm, smv_manual_checks)

def add_common_numbers(nums):
    ret = nums

    ue_uip = Number("ue_uip", "0", "5", ["0", "nat_uip"])
    ue_eip = Number("ue_eip", "0", "5", ["0", "3", "network_eip"])
    network_eip = Number("network_eip", "0", "5", ["0", "dns_eip", "adv_aip"])

    nums.append(ue_uip)
    nums.append(ue_eip)
    nums.append(network_eip)
    return ret

def add_common_manual_checks(checks):
    ret = checks
    checks.append("dns_port := 1")
    checks.append("ike_port := 2")
    checks.append("sip_port := 3")

    checks.append("nat_nip := 1")
    checks.append("nat_uip := 2")
    checks.append("epdg_eip := 3")
    checks.append("epdg_dip := 0")
    checks.append("ue_dip := 4")
    checks.append("dns_eip := 3")
    checks.append("dns_dip := 4")
    checks.append("adv_aip := 5")

    #checks.append("ue_eip := 3")

    return ret

def prepare_constraints_for_entities(config, types):
    ret = {}
    logging.info("entity types: {}".format(types))
    for t in types:
        key = "Constraints-for-{}".format(t)
        if key not in config:
            continue
        ret[t] = {}
        with open(config[key], "r") as f:
            for line in f:
                if line[0] == "#":
                    rule = line[1:].strip()
                    ret[t][rule] = {}
                    continue

                if line.strip() == '':
                    continue

                k, v = line.strip().split(": ")
                ret[t][rule][k] = v
    return ret

def prepare_constraints_for_contexts(config, types):
    ret = {}
    logging.info("Types: {}".format(types))
    for t in types:
        key = "Constraints-for-{}".format(t)
        if key not in config:
            continue
        ret[t] = {}

        with open(config[key], "r") as f:
            keys = f.readline().strip().split(", ")
            idx = 0
            for line in f:
                if line.startswith("#"):
                    continue
                if len(line.strip()) == 0:
                    continue
                ret[t][idx] = {}
                tmp = line.strip().split(", ")
                for i in range(len(keys)):
                    ret[t][idx][keys[i]] = tmp[i].strip()
                idx += 1
    return ret

def make_combinations(count):
    logging.debug("count: {}".format(count))
    ret = {}
    ret[0] = []
    for c in count:
        num = len(ret)
        logging.debug("c: {}, num: {}".format(c, num))
        start_idx = 0
        
        for i in range(c):
            for j in range(num):
                ret[start_idx + j] = copy.deepcopy(ret[j])
            start_idx += num
        
        if c == 0:
            for i in range(num):
                ret[i].append(-1)
        else:
            for i in range(c):
                start_idx = i * num
                for j in range(num):
                    ret[start_idx + j].append(i)

    logging.debug("combinations: {}".format(ret))
    return list(ret.values())

def substitution(s, entity, constraints_for_entity):
    ret = s
    entity_prefix = entity.lower()
    #lst = ["dst_port_check", "dst_addr_check", "rcvd_dst_port", "rcvd_dst_addr", "sent_dst_port", "sent_dst_addr", "check_"]
    lst = ["dst_port_check", "dst_addr_check", "rcvd_dst_addr", "rcvd_dst_port", "check_"]
    channels = ["channel_state"]

    if "my_ip" in ret:
        ret = ret.replace("my_ip", constraints_for_entity[entity]["Substitution"]["my_ip"])

    if "my_address" in ret:
        ret = ret.replace("my_address", constraints_for_entity[entity]["Substitution"]["my_address"])

    if "_me" in ret:
        ret = ret.replace("_me", "_{}".format(entity_prefix))

    if "my_imid" in ret:
        ret = ret.replace("my_imid", constraints_for_entity[entity]["Substitution"]["my_imid"])

    if "my_rmid" in ret:
        ret = ret.replace("my_rmid", constraints_for_entity[entity]["Substitution"]["my_rmid"])

    if "my_tbs_ike_msg" in ret:
        ret = ret.replace("my_tbs_ike_msg", constraints_for_entity[entity]["Substitution"]["my_tbs_ike_msg"])

    if "my_tbs_sip_msg" in ret:
        ret = ret.replace("my_tbs_sip_msg", constraints_for_entity[entity]["Substitution"]["my_tbs_sip_msg"])

    if "my_tbs_eap_msg" in ret:
        ret = ret.replace("my_tbs_eap_msg", constraints_for_entity[entity]["Substitution"]["my_tbs_eap_msg"])

    if "other_imid" in ret:
        ret = ret.replace("other_imid", constraints_for_entity[entity]["Substitution"]["other_imid"])

    if "other_rmid" in ret:
        ret = ret.replace("other_rmid", constraints_for_entity[entity]["Substitution"]["other_rmid"])

    if "my_ike_retransmission" in ret:
        ret = ret.replace("my_ike_retransmission", constraints_for_entity[entity]["Substitution"]["my_ike_retransmission"])

    if "other_ike_retransmission" in ret:
        ret = ret.replace("other_ike_retransmission", constraints_for_entity[entity]["Substitution"]["other_ike_retransmission"])

    if "my_sip_retransmission" in ret:
        ret = ret.replace("my_sip_retransmission", constraints_for_entity[entity]["Substitution"]["my_sip_retransmission"])

    if "other_sip_retransmission" in ret:
        ret = ret.replace("other_sip_retransmission", constraints_for_entity[entity]["Substitution"]["other_sip_retransmission"])

    if "my_last" in ret:
        ret = ret.replace("my_last", constraints_for_entity[entity]["Substitution"]["my_last"])

    if "other_last" in ret:
        ret = ret.replace("other_last", constraints_for_entity[entity]["Substitution"]["other_last"])

    if "rnum" in ret:
        ret = ret.replace("rnum", "{}_rnum".format(entity_prefix))

    for sub in lst:
        ret = ret.replace(sub, "{}_{}".format(entity_prefix, sub))

    for channel in channels:
        ret = ret.replace(channel, "{}-to-other-{}".format(entity_prefix, channel))

    return ret

def refine_model(fsm, entity, constraints_for_entity):
    ret = fsm
    entity_prefix = "{}".format(entity.lower())
    entity_prefix_len = len(entity_prefix)
    words = ["dst_port_check", "dst_addr_check", "rcvd_dst_port", "rcvd_dst_addr", "sent_dst_port", "sent_dst_addr", "channel_state", "check_", "retransmission_needed", "other_imid", "last"]

    for idx in range(len(fsm)):
        if idx == VAR_INDEX:
            variables = fsm[idx]
            for var in variables:
                if "retransmission_needed" in var.varname or "my_last" in var.varname or "other_last" in var.varname:
                    varname = var.varname
                else:
                    varname = "{}_{}".format(entity_prefix, var.varname)
                varname = substitution(varname, entity, constraints_for_entity)
                var.set_varname(varname)

                if "is_ue" in varname: 
                    if entity_prefix == "ue":
                        var.set_initial_value("TRUE")
                        var.set_possible_values(["TRUE"])
                    else:
                        var.set_initial_value("FALSE")
                        var.set_possible_values(["FALSE"])

                #if "internal_phymac_ip" in varname:
                #    if entity_prefix == "ue":
                #        var.set_initial_value("wifi")
                #    else:
                #        var.set_initial_value("eth")

                possible_values = var.possible_values
                lst = []
                if possible_values:
                    for p in possible_values:
                        p = substitution(p, entity, constraints_for_entity)
                        lst.append(p)
                    var.set_possible_values(lst)

        if idx == NUM_INDEX:
            numbers = fsm[idx]
            for num in numbers:
                if "my_imid" in num.name or "my_rmid" in num.name:
                    num.set_numname(substitution(num.name, entity, constraints_for_entity))
                else:
                    num.set_numname("{}_{}".format(entity_prefix, num.name))
                possible_values = num.possible_values
                lst = []
                for p in possible_values:
                    if p == "uip" or p == "eip" or p == "dip" or p == "target_addr" or p == "target_port":
                        p = "{}_{}".format(entity_prefix, p)

                    if "rcvd_src" in p:
                        p = "{}_{}".format(entity_prefix, p)

                    if "rcvd_dst" in p:
                        p = "{}_{}".format(entity_prefix, p)

                    if "sent_src" in p:
                        p = "{}_{}".format(entity_prefix, p)

                    if "sent_dst" in p:
                        p = "{}_{}".format(entity_prefix, p)

                    if p == "rnum+1":
                        p = "{}_rnum+1".format(entity_prefix)

                    if p == "my_ip":
                        p = constraints_for_entity[entity]["Substitution"][p]

                    if "my_imid" in p:
                        key = "my_imid"
                        p = p.replace(key, constraints_for_entity[entity]["Substitution"][key])

                    if "my_rmid" in p:
                        key = "my_rmid"
                        p = p.replace(key, constraints_for_entity[entity]["Substitution"][key])

                    if "other_imid" in p:
                        key = "other_imid"
                        p = p.replace(key, constraints_for_entity[entity]["Substitution"][key])

                    if "other_rmid" in p:
                        key = "other_rmid"
                        p = p.replace(key, constraints_for_entity[entity]["Substitution"][key])

                    lst.append(p)
                num.set_possible_values(lst)

        if idx == FSM_INDEX:
            fsm_label = fsm[idx].fsm_label
            fsm[idx].fsm_label = "{}_{}".format(entity, fsm_label)

            transitions = fsm[idx].transitions
            for transition in transitions:
                if len(transition.condition) > 0:
                    logging.debug("condition: {}".format(transition.condition))
                    transition.transition_label = "{}_{}".format(entity, transition.transition_label)
                    tmp = transition.condition.split("&")
                    for k in range(len(tmp)):
                        tmp[k] = tmp[k].strip()

                        exists = False
                        for w in words:
                            if w in tmp[k]:
                                exists = True

                        if not exists:
                            if tmp[k][0] == "!":
                                negate = True
                                tmp[k] = tmp[k][1:]
                            else:
                                negate = False

                            if negate:
                                tmp[k] = "!{}_{}".format(entity_prefix, tmp[k].strip())
                            else:
                                tmp[k] = "{}_{}".format(entity_prefix, tmp[k].strip())

                    revised = ' & '.join(tmp)
                    revised = substitution(revised, entity, constraints_for_entity)
                    transition.set_condition(revised)
                if len(transition.actions) > 0:
                    for action in transition.actions:
                        action_label = action.action_label
                        show = False
                        action_label = substitution(action_label, entity, constraints_for_entity)
                        if not (action_label[0:3] == "ue_" or action_label[0:5] == "epdg_"):
                            action_label = "{}_{}".format(entity_prefix, action_label)
                        action.set_action_label(action_label)

        if idx == MANUAL_INDEX:
            manual = fsm[idx]
            lst = []
            for m in manual:
                lst.append(substitution(m, entity, constraints_for_entity))
            fsm[idx] = lst
    logging.debug("{}-{}> fsm: {}".format(entity, fsm[FSM_INDEX].fsm_label, fsm))

    return ret

def revise_model(fsm, entity):
    ret = fsm
    f = fsm[FSM_INDEX]
    transitions = f.transitions
    entity_prefix = entity.lower()

    new_transitions = []
    for t in transitions:
        tmp = t.condition.split("&")
        maintain = True
        for token in tmp:
            token = token.strip()
            if "rcvd_dst_port" in token and entity.lower() == "epdg" and "dns_port" in token:
                maintain = False
                break
            if "rcvd_dst_port" in token and entity.lower() == "dns" and "ike_port" in token:
                maintain = False
                break
            if "rcvd_dst_port" in token and entity.lower() == "dns" and "sip_port" in token:
                maintain = False
                break
            if "target_port" in token and entity.lower() == "epdg" and "dns_port" in token:
                maintain = False
                break
            if "target_port" in token and entity.lower() == "dns" and "ike_port" in token:
                maintain = False
                break
            if "target_port" in token and entity.lower() == "dns" and "sip_port" in token:
                maintain = False
                break

        if maintain:
            new_transitions.append(t)
    f.transitions = new_transitions

    return ret

def remove_internal_channel(fsm, keyword):
    ret = fsm
    variables = fsm[VAR_INDEX]
    f = fsm[FSM_INDEX]
    transitions = f.transitions
    
    var = []
    for v in variables:
        varname = v.varname
        if "internal" in varname and keyword in varname:
            logging.debug("label: {}, variable: {}, keyword: {}".format(f.fsm_label, varname, keyword))
            continue
        var.append(v)
    ret[VAR_INDEX] = var

    for t in transitions:
        tmp = t.condition.split("&")
        cond = []
        for token in tmp:
            token = token.strip()
            if "internal" in token and keyword in token:
                continue
            cond.append(token)

        if len(cond) > 0:
            t.set_condition(" & ".join(cond))
        else:
            t.set_condition("")

        tmp = t.actions
        #logging.info("actions: {}".format(tmp))
        act = []
        for action in tmp:
            #logging.info("action_label: {}".format(action.action_label))
            if "internal" in action.action_label and keyword in action.action_label:
                continue
            act.append(action)
        t.set_actions(act)

    new_transitions = []
    for t in transitions:
        if t.condition == "":
            continue
        new_transitions.append(t)
    f.transitions = new_transitions

    return ret

def generate_model_variants(initial_fsms):
    ret = {}
    for label in initial_fsms:
        fsm = initial_fsms[label][5]
        logging.debug("fsm: {}".format(fsm))
        states = fsm.states
        init_state = fsm.init_state

        transitions = {}
        fsms = []
        for transition in fsm.transitions:
            if transition.start not in transitions:
                transitions[transition.start] = {}
            if transition.condition not in transitions[transition.start]:
                transitions[transition.start][transition.condition] = []
            transitions[transition.start][transition.condition].append(transition)

        count = []
        
        for start in transitions:
            for condition in transitions[start]:
                nt = len(transitions[start][condition])
                if nt > 1:
                    logging.info("{}> underspecification on the state {} on the condition: {} (# of transitions: {})".format(label, start, condition, nt))
                count.append(nt)
        combinations = make_combinations(count)
        logging.debug("{}> combinations: {}".format(label, combinations))

        for c in combinations:
            trans = []
            idx = 0
            for start in transitions:
                for condition in transitions[start]:
                    trans.append(transitions[start][condition][c[idx]])
                    idx += 1
                    
            fsms.append(FSM(fsm.fsm_label, fsm.states, fsm.init_state, trans))
                
        for f in fsms:
            variant = []
            for i in range(len(initial_fsms[label])):
                if i == FSM_INDEX:
                    variant.append(f)
                else:
                    variant.append(initial_fsms[label][i])
            logging.debug("initial_fsms[label]: {}".format(initial_fsms[label]))
            logging.debug("variant: {}".format(variant))
            if label not in ret:
                ret[label] = []
            ret[label].append(variant)

    return ret

def take_interfaces(fsms, entity, constraints_for_entity):
    interfaces = constraints_for_entity[entity]["Constraints"]["Interface"]
    logging.info("interfaces: {}".format(interfaces))
    if "eth" in interfaces:
        ret = [interfaces[0]]
    else:
        ret = interfaces

    return ret

def generate_protocol_stacks_per_entity(model_variants, entity_types, constraints_for_entity):
    ret = {}
    lst = ["PHYMAC", "IP", "UDP", "IKE-INITIATOR", "IKE-RESPONDER", "SIP-CLIENT", "SIP-SERVER", "DNS-CLIENT", "DNS-SERVER"]

    for e in entity_types:
        ret[e] = []
        count = []
        total = 1
        for protocol in lst:
            logging.debug("{}> {} - {}".format(e, protocol, constraints_for_entity[e]["Protocol Stack"][protocol]))
            if constraints_for_entity[e]["Protocol Stack"][protocol] == "yes":
                #if protocol == "PHYMAC":
                #    if e == "UE":
                #        num = 2
                #    else:
                #        num = 1
                #else:
                num = len(model_variants[protocol])
                total *= num
                count.append(num)
            else:
                count.append(0)
        logging.debug("{}> count: {}".format(e, count))
        logging.debug("total: {}".format(total))
        combinations = make_combinations(count)

        logging.debug("{}> combinations: {}".format(e, combinations))
        logging.info("{}> # of protocol stacks: {}".format(e, len(combinations)))

        for c in combinations:
            ps = {}
            idx = 0
            for num in c:
                if num >= 0:
                    protocol = lst[idx]
                    fsm_label = "{}-{}".format(e, protocol)
                    fsm = copy.deepcopy(model_variants[protocol][num])
                    fsm = refine_model(fsm, e, constraints_for_entity)
                    ps[fsm_label] = fsm
                idx += 1
            ret[e].append(ps)

        if constraints_for_entity[e]["Protocol Stack"]["IKE-INITIATOR"] == "no" and constraints_for_entity[e]["Protocol Stack"]["IKE-RESPONDER"] == "no":
            for ps in ret[e]:
                for k in ps:
                    ps[k] = remove_internal_channel(ps[k], "ike")
                    ps[k] = revise_model(ps[k], e)

        if constraints_for_entity[e]["Protocol Stack"]["SIP-CLIENT"] == "no" and constraints_for_entity[e]["Protocol Stack"]["SIP-SERVER"] == "no":
            for ps in ret[e]:
                for k in ps:
                    ps[k] = remove_internal_channel(ps[k], "sip")
                    ps[k] = revise_model(ps[k], e)

        if constraints_for_entity[e]["Protocol Stack"]["DNS-CLIENT"] == "no" and constraints_for_entity[e]["Protocol Stack"]["DNS-SERVER"] == "no":
            for ps in ret[e]:
                for k in ps:
                    ps[k] = remove_internal_channel(ps[k], "dns")
                    ps[k] = revise_model(ps[k], e)
    return ret

def apply_constraints(scenario, constraints_for_context, num):
    TEST_IDX = -1
    ret = False

    for k in constraints_for_context:
        if k == "UE-DNS":
            continue

        for idx in constraints_for_context[k]:
            protocol = constraints_for_context[k][idx]["protocol"].strip()
            from_entity = constraints_for_context[k][idx]["from_entity"].strip()
            from_state_in = constraints_for_context[k][idx]["from_state_in"].strip()
            from_condition = constraints_for_context[k][idx]["from_condition"].strip()
            from_state_out = constraints_for_context[k][idx]["from_state_out"].strip()
            from_action = constraints_for_context[k][idx]["from_action"].strip()
            to_entity = constraints_for_context[k][idx]["to_entity"].strip()
            to_state_in = constraints_for_context[k][idx]["to_state_in"].strip()
            to_condition = constraints_for_context[k][idx]["to_condition"].strip()
            to_state_out = constraints_for_context[k][idx]["to_state_out"].strip()
            to_action = constraints_for_context[k][idx]["to_action"].strip()

            from_result = False
            to_result = False

            if num == TEST_IDX:
                logging.info("Constraints: protocol: {}, from_entity: {}, from_state_in: {}, from_condition: {}, from_state_out: {}, from_action: {}, to_entity: {}, to_state_in: {}, to_condition: {}, to_state_out: {}, to_action: {}".format(protocol, from_entity, from_state_in, from_condition, from_state_out, from_action, to_entity, to_state_in, to_condition, to_state_out, to_action))

            for label in scenario:
                if protocol.upper() in label and from_entity in label:
                    if num == TEST_IDX:
                        logging.info("label: {}, fsm: {}".format(label, scenario[label][FSM_INDEX]))
                    from_fsm = scenario[label][FSM_INDEX]
                    from_transitions = from_fsm.transitions

                    for t in from_transitions:
                        if from_state_in == t.start and from_state_out == t.end and from_condition in t.condition:
                            if num == TEST_IDX:
                                logging.info("label: {}, from_state_in: {}, from_state_out: {}, t.start: {}, t.end: {}, from_action: {}".format(label, from_state_in, from_state_out, t.start, t.end, from_action))
                            for action in t.actions:
                                if num == TEST_IDX:
                                    logging.info("action_label: {}, from_action: {}".format(action.action_label, from_action))
                                if from_action in action.action_label:
                                    from_result = True

                            if num == TEST_IDX:
                                logging.info("from_state_in: {}, from_state_out: {}, t.condition: {}, t.actions: {}".format(from_state_in, from_state_out, t.condition, t.actions))

                if protocol.upper() in label and to_entity in label:
                    if num == TEST_IDX:
                        logging.info("label: {}, fsm: {}".format(label, scenario[label][FSM_INDEX]))
                    to_fsm = scenario[label][FSM_INDEX]
                    to_transitions = to_fsm.transitions

                    for t in to_transitions:
                        if to_state_in == t.start and to_state_out == t.end and to_condition in t.condition:
                            for action in t.actions:
                                if to_action in action.action_label:
                                    to_result = True

                            if num == TEST_IDX:
                                logging.info("to_state_in: {}, to_state_out: {}, t.condition: {}, t.actions: {}".format(to_state_in, to_state_out, t.condition, t.actions))

            if from_result == True and to_result == True:
                if num == TEST_IDX:
                    logging.info("from: True, to: True")
                ret = True
            elif from_result == True and to_result == False:
                if num == TEST_IDX:
                    logging.info("from: True, to: False")
                ret = False
            elif from_result == False and to_result == True:
                if num == TEST_IDX:
                    logging.info("from: False, to: True")
                ret = True
            else:
                if num == TEST_IDX:
                    logging.info("from: False, to: False")
                ret = True
            if num == TEST_IDX:
                logging.info("")

            if not ret:
                if num == TEST_IDX:
                    logging.info("ret is False")
                break

        if not ret:
            if num == TEST_IDX:
                logging.info("ret is False")
            break

    if num == TEST_IDX:
        logging.info("ret: {}".format(ret))
    return ret

def generate_scenarios(protocol_stacks, entity_types, constraints_for_context):
    ret = {}
    count = []
    for e in entity_types:
        logging.debug("{}> {}".format(e, len(protocol_stacks[e])))
        count.append(len(protocol_stacks[e]))
    combinations = make_combinations(count)
    logging.debug("combinations ({}): {}".format(len(combinations), combinations))
        
    idx = 0
    init_num = len(combinations)
    for c in combinations:
        tmp = {}
        for i in range(len(entity_types)):
            ps = protocol_stacks[entity_types[i]][c[i]]
            for label in ps:
                tmp[label] = ps[label]
        insert = apply_constraints(tmp, constraints_for_context, idx)
        if insert:
            ret[idx] = {}
            for label in tmp:
                ret[idx][label] = tmp[label]
            idx += 1

    for i in ret:
        logging.debug("scenario {}: {}".format(i, ret[i]))
    final_num = len(ret)
    return init_num, final_num, ret

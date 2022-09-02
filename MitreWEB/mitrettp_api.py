import re
import json
from mitrettpdb import MitreTTPDatabase, to_phase_name, get_config, CUSTOM_ALERT_TABLE, RELATION_TABLE, \
    SUB_TECHNIQUE_TABLE, OTHER_SUB_TECHNIQUE, CONROL_VARIABLE, CUSTOM_RULE_TABLE
from mysql.connector import errors

"""
Json to return 
 [
   {
 		"tactic": "initial-access",
 		"patternId": "T1078.001"
 	},
 	{
 		"tactic": "discovery",
 		"patternId": "T1016.001"
 	}
 ]
 
 else 
 
 [
    {
        "error" : "[..]"
    }
 ]
"""
def get_mitre_category(data: dict) -> json:
    """
    Function used through POST request to get Mitre categories of a specified alert_id if there is almost a match in CUSTOM_RULE_TABLE
    :param data: dict with following fileds: "tool", "id", "raw"
    :return: a json with an array containing "tactic", "patternId" keys
    """
    ttps = []  # List with data ,to return
    try:
        tool = data['tool']
        alert_id = data['id']
        raw_data = data['raw']
    except Exception as e:
        print("Error while reading input json: ", e)
        return json.dumps({"errors": f'Error while reading input json: {e}'})

    conn_info = get_config()
    try:
        MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])
    except errors.Error as e:
        return json.dumps({"error": f'Failed to connect to {conn_info["schema"]} database'})

    raw_tactics = re.findall(r'TA\d{4}', raw_data)                                                  # Check possible tactics in raw data
    raw_techniques = re.findall(r'T\d{4}\.\d{3}|T\d{4}', raw_data)                                  # Check possible techniques and techniques.sub_techniques in raw data

    # Check if there is an alert in CUSTOM_ALERT_TABLE with the alert_id required. Used for further insertions
    query = f'SELECT * FROM {CUSTOM_ALERT_TABLE} WHERE id LIKE "{alert_id}";'
    if len(MitreDB.execute_query(query)) < 1:                                                       # Create alert if not present
        query = f'INSERT INTO {CUSTOM_ALERT_TABLE} VALUES ("{alert_id}", {tool}, 0, "");'           # 0 will be set to 1 in the last if-else
        MitreDB.execute_query(query)

    # If there are techniques matches in raw
    if raw_techniques:
        categories_found = []
        for t_id_extended in raw_techniques:                                                        # For every technique found
            t_id = re.search(r'T\d{4}', t_id_extended).group()                                      # Never None

            # Check if there are tactics in raw, else get all tactics in Mitre DB related to every technique in raw data
            if not raw_tactics:
                query = f'SELECT ta_id FROM {RELATION_TABLE} WHERE t_id LIKE "{t_id}";'
                relations = MitreDB.execute_query(query)
                tactics = []
                for r in relations:                                                                 # Necessary to have a list of ta_ids instead of a list of tuples
                    tactics.append(r[0])
            else:
                tactics = raw_tactics

            for ta_id in tactics:  # For every tactic found
                only_tech = False                                                                   # Flag to insert an entry with "void" or "Other" as subt_id
                if exist_subs := re.search(r'(?<=\.)\d{3}', t_id_extended):                         # If it has also a sub-technique
                    subt_id = exist_subs.group()                                                    # get its subt_id

                query = f'SELECT * FROM {SUB_TECHNIQUE_TABLE} WHERE id LIKE "{t_id}";'              # Check if the technique has some sub-technique in Mitre Framework
                if len(MitreDB.execute_query(query)):                                               # Info about possible sub-techniques of the technique "t"
                    t_sub_info = f'{OTHER_SUB_TECHNIQUE}'                                           # If yes put "Other"
                else:
                    t_sub_info = f'{CONROL_VARIABLE}'                                               # If not put "void"

                if exist_subs:
                    query = f'INSERT INTO {CUSTOM_RULE_TABLE} VALUES ("{alert_id}","{ta_id}","{t_id}","{subt_id}");'    # If exist_subs != None --> subt_id != None
                    e = MitreDB.execute_query(query)
                    if e is None or 'duplicate entry' in str(e).lower():                                                # Exception thrown due to wrong relation between tactic, technique and sub-technique managed by commit_query
                        categories_found.append({
                            'tactic': to_phase_name(MitreDB.get_db_tactics(ta_id).pop().get_name()),
                            'patterId': f'{t_id}.{subt_id}' if exist_subs else f'{t_id}'
                        })
                        continue                                                                                        # Unnecessary due to if condition, put anyway to avoid useless comparisons
                    else:
                        only_tech = True                                                                                # Insertion of a rule with sub-technique field failed, flag to try to add a less restricting rule (only tactic and technique)

                # If sub-technique insertion failed or technique found hasn't sub-technique, insertion of a technique without sub-technique (sub-technique void or Other based on Mitre framework )
                if exist_subs is None or only_tech:
                    query = f'INSERT INTO {CUSTOM_RULE_TABLE} VALUES ("{alert_id}","{ta_id}","{t_id}","{t_sub_info}");'
                    e = MitreDB.execute_query(query)
                    if e is None or 'duplicate entry' in str(e).lower():
                        categories_found.append({
                            'tactic': to_phase_name(MitreDB.get_db_tactics(ta_id).pop().get_name()),
                            'patterId': f'{t_id}.{subt_id}' if exist_subs else f'{t_id}'
                        })

        return json.dumps(categories_found)

    # For all categories matched with the alert_id, insert into json each category
    query = f'SELECT ta_id, t_id, subt_id FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert_id}";'
    if len(categories := MitreDB.execute_query(query)):
        for cat in categories:
            ta_id = cat[0]
            t_id = cat[1]
            subt_id = cat[2]  # Could be "void"

            tactic_name = MitreDB.get_db_tactics(ta_id).pop().get_name()
            phase_name = to_phase_name(tactic_name)
            # If TA0001 T1011 void --> append (TA0001,T1011)
            # If TA0001 T1011 001 --> append (TA0001,T1011.001)
            if f'{CONROL_VARIABLE}' not in subt_id and f'{OTHER_SUB_TECHNIQUE}' not in subt_id:
                patternId = '.'.join([t_id, subt_id])
            else:
                patternId = t_id
            ttps.append({"tactic": phase_name, "patternId": patternId})

        return json.dumps(ttps)
    else:
        query = f'SELECT miss_num FROM {CUSTOM_ALERT_TABLE} WHERE id LIKE "{alert_id}";'
        if not isinstance(res_num := MitreDB.execute_query(query), Exception) or not None:                              # If no error occurred
            query = f'UPDATE {CUSTOM_ALERT_TABLE} SET miss_num = {res_num[0][0] + 1} WHERE id LIKE "{alert_id}";'
            MitreDB.execute_query(query)

    return json.dumps([])

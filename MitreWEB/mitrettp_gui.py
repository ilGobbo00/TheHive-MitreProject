import re


from mitrettpdb import get_config, MitreTTPDatabase, CONROL_VARIABLE, CUSTOM_RULE_TABLE, OTHER_SUB_TECHNIQUE, \
    TOOL_TABLE, CUSTOM_ALERT_TABLE
from flask import Flask, session, render_template, request, Response
from flask_session import Session
import mitrettp_api

app = Flask(__name__)
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)

SEPARATOR = "new_line"


@app.route('/', methods=['GET', 'POST'])
def home():
    conn_info = get_config()
    try:
        MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])
    except Exception as e:
        return render_template('Error.html', info=f'Error while connection to DB: {str(conn_info) + " -> " + str(e)}')

    if request.form.get('choise') == 'Display categories':
        return existing_categories()
    elif request.form.get('choise') == 'Modify rules':
        session['DB'] = MitreDB.get_db_data()
        return modify_rules()
    elif request.form.get('choise') == 'Update categories':
        msg = MitreDB.fill_mitre_tables()
        if msg is not None:
            return render_template("Home.html", message="Mitrettp database updated with some error/warnings ", errors=msg)
        else:
            return render_template("Home.html", message="Mitrettp database correctly updated")
    elif request.form.get('choise') == 'Modify tools':
        return modify_tools()
    elif request.form.get('choise') == 'Modify alerts':
        return modify_alerts()
    else:
        return render_template("Home.html")


@app.route('/ExistingCategories', methods=['GET', 'POST'])
def existing_categories():
    """
    Function to display a table with the category data selected
    :return: MitreCategories.html with a corresponding table to category selected
    """
    conn_info = get_config()
    MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])

    if request.form.get('visualization') == 'Tactics':
        tactics = MitreDB.get_db_tactics()  # Obtain all tactics in database
        return render_template("MitreCategories.html", showRes=True, showTot=False, mitre_element=tactics,
                               last_choise=0, title="TACTICS", CONROL_VARIABLE=CONROL_VARIABLE)
    elif request.form.get('visualization') == 'Techniques':
        techniques = MitreDB.get_db_techniques()  # Obtain all techniques in database
        return render_template("MitreCategories.html", showRes=True, showTot=False, mitre_element=techniques,
                               last_choise=1, title="TECHNIQUES", CONROL_VARIABLE=CONROL_VARIABLE)
    elif request.form.get('visualization') == 'Sub-Techniques':
        sub_techniques = MitreDB.get_db_subtechniques()  # Obtain all sub-techniques in database
        return render_template("MitreCategories.html", showRes=True, showTot=False, mitre_element=sub_techniques,
                               last_choise=2, title="SUB TECHNIQUES", CONROL_VARIABLE=CONROL_VARIABLE)
    elif request.form.get('visualization') == 'All Categories':
        return render_template("MitreCategories.html", showRes=False, showTot=True, mitre_trees=MitreDB.get_db_data(),
                               last_choise=3, title="ALL CATEGORIES", CONROL_VARIABLE=CONROL_VARIABLE)
    elif request.form.get('choise'):
        return render_template("MitreCategories.html", title="MITRE FRAMEWORK", showRes=False, last_choise=4)
    else:
        return render_template("MitreCategories.html", title="MITRE FRAMEWORK", showRes=False, last_choise=-1)


@app.route('/ModifyRules', methods=['GET', 'POST'])
def modify_rules():
    """
    Add and remove the matches selected by the user
    :return: ModifyRules.html with updated data
    """
    conn_info = get_config()
    MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])

    check_add = request.form.get('add')
    rules_to_add = request.form.getlist('rules')
    categories_to_add = request.form.getlist('categories_to_add')

    check_remove = request.form.get('delete')
    alert_to_remove = request.form.getlist('alert_to_remove')
    categories_to_remove = request.form.getlist('categories_to_remove')

    if check_add and (len(rules_to_add) < 1 or len(categories_to_add) < 1):
        error_miss = "Select almost an alert and a Mitre category"
    else:
        error_miss = None

    if check_remove and len(alert_to_remove) < 1 and len(categories_to_remove) < 1:
        error_match = "Select almost an element"
    else:
        error_match = None

    if check_add and len(rules_to_add) > 0 and len(categories_to_add) > 0:
        upload_data(rules_to_add, categories_to_add)

    if check_remove and (len(alert_to_remove) > 0 or len(categories_to_remove) > 0):
        remove_data(alert_to_remove, categories_to_remove)

    db_data = session['DB']

    # Getting all rules that are in the DB
    all_alerts = MitreDB.get_db_alerts(order_by="miss_num", mode="DESC")
    tools = MitreDB.get_db_tools()
    if len(all_alerts) == 0:
        all_alerts = None

    # Getting rules with almost a match
    matched_rules = MitreDB.get_db_rules()
    if len(matched_rules) == 0:
        matched_rules = None

    return render_template("ModifyRules.html", title="MODIFY RULES", mitre_trees=db_data,
                           alerts=all_alerts, tools=tools,
                           error_miss=error_miss, matched_rules=matched_rules, error_match=error_match,
                           CONROL_VARIABLE=CONROL_VARIABLE)


# Example (data from ModifyRules.html):
#   AAA.003 --> TA0001.root
#   ABC.1       TA0009.root
#               TA0009.T1043
#               TA0011.T1132.002
def upload_data(alerts_to_add, categories):
    """
    Function to insert in custom_rule all mitre category in categories matching them to alerts_to_add elements
    :param alerts_to_add: list of alerts to match with every category in @categories
    :param categories: all categories selected
    """
    conn_info = get_config()
    try:
        MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])
    except Exception as e:
        return render_template('Error.html', info=f'Error while connection to DB: {str(conn_info) + " ->" + str(e)}')

    all_inserted = []                                                   # List to contain categories whose all sub-categories are already inserted
    # TACTICS
    # First check if some tactics were selected
    tactic_pattern = re.compile(r'.*root$')                             # Search for tactics
    tactics = list(filter(tactic_pattern.match, categories))            # ["TA0009.root", "TA0001.root"]
    for ta in tactics:                                                  # Main loop analyzes tactics to optimize the number of call to get_db_techniques for every rule
        ta_id = re.search(r'\w+(?=\.root)', ta).group()                 # Get the id of the tactic
        ta_technique = MitreDB.get_db_techniques(tactic_id=ta_id)       # Get all techniques of a tactic
        for r in alerts_to_add:                                         # for every alert selected
            for ta_tech in ta_technique:                                # insertion of an entry
                subt_t = MitreDB.get_db_subtechniques(ta_tech.get_id())
                if len(subt_t) > 0:                                     # If a specific technique has sub-technique, insert them all
                    for s in subt_t:
                        sub_id = re.search(r'(?<=\.)\d+', s.get_id()).group()

                        # Remove other previous entries inserted by selecting a technique and any sub-technique
                        query = f'DELETE FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{r}" AND ta_id LIKE "{ta_id}" AND t_id LIKE "{ta_tech.get_id()}" AND subt_id LIKE "{OTHER_SUB_TECHNIQUE}";'
                        MitreDB.execute_query(query)

                        # Insert of all sub-techniques of the technique
                        query = f'INSERT INTO {CUSTOM_RULE_TABLE} VALUES ("{r}", "{ta_id}", "{ta_tech.get_id()}", "{sub_id}");'
                        MitreDB.execute_query(query)
                else:
                    query = f'INSERT INTO {CUSTOM_RULE_TABLE} VALUES ("{r}", "{ta_id}", "{ta_tech.get_id()}", "{CONROL_VARIABLE}");'
                    MitreDB.execute_query(query)
        all_inserted.append(ta_id)                                      # Adding tactics whose techniques are all just inserted

    # TECHNIQUES
    # Cases (for techniques):
    #   TA0009.T1043        (technique without sub-technique)
    #   TA0011.T1132.xxx    (technique with sub-technique)
    technique_pattern = re.compile(r'TA\d+\.T\d+$|TA\d+\.T\d+\.xxx')    # Find all technique data (not sub-technique)
    technique = list(filter(technique_pattern.match, categories))
    for tech in technique:                                              # Main loop analyzes techniques to optimize number of call to get_db_subtechniques(tech_id=tech_id) for every rule
        ta_id = re.search(r'TA\w+', tech).group()                       # Select TA____
        if ta_id in all_inserted:                                       # If a technique was inserted with the first for loop
            continue                                                    # skip this cycle
        tech_id = re.search(r'T\d+', tech).group()                      # Select T____
        for r in alerts_to_add:
            if re.search(r'xxx', tech) is None:
                query = f'INSERT INTO {CUSTOM_RULE_TABLE} VALUES ("{r}", "{ta_id}", "{tech_id}", "{CONROL_VARIABLE}");'
            else:
                query = f'INSERT INTO {CUSTOM_RULE_TABLE} VALUES ("{r}", "{ta_id}", "{tech_id}", "{OTHER_SUB_TECHNIQUE}");'
            MitreDB.execute_query(query)

    # SUB-TECHNIQUES
    # Example of input: TA0001.T1078.001
    sub_technique_pattern = re.compile(r'.*T\d+\.\d+$')
    sub_techniques = list(filter(sub_technique_pattern.match, categories))
    for r in alerts_to_add:                                                         # For every rules
        for sub_t in sub_techniques:                                                # there will be an entry if a sub-technique was selected
            ta_id = re.search(r'TA\d+', sub_t).group()                              # Select TA____
            if ta_id in all_inserted:                                               # If a sub_technique was inserted with the first for loop
                continue                                                            # skip this cycle

            t_id = re.search(r'T\d+', sub_t).group()
            subt_id = re.search(r'(?<=\.)\d+', sub_t).group()
            query = f'INSERT INTO {CUSTOM_RULE_TABLE} VALUES ("{r}", "{ta_id}", "{t_id}", "{subt_id}");'
            MitreDB.execute_query(query)


# Esample of (max) category data: AAD.1.TA0001.T1078.002
def remove_data(alert_to_remove, categories):
    """
    Function used to remove from custom_rules the selected categories of each alert
    :param alert_to_remove: alerts selected
    :param categories: categories selected
    """
    conn_info = get_config()
    MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])

    # Remove all selected alerts
    for alert in alert_to_remove:
        query = f'DELETE FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert}";'
        MitreDB.execute_query(query)

    # Remove all selected tactics and their sub-categories using a single SQL query
    tactic_pattern = re.compile(r'.*TA\d+\.xxx')                             # Select only [..]TA____.xxx
    tactics = list(filter(tactic_pattern.match, categories))
    for ta in tactics:  # ASC.8.TA0001.xxx
        try:
            alert_id = re.search(r'.*(?=.TA.*)', ta).group()  # ASC.8
            tactic_id = re.search(r'TA\d+', ta).group()  # TA0001
        except Exception as e:
            print("Error trying to identify elements got from html: ", e)
            continue

        query = f'DELETE FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert_id}" AND ta_id LIKE "{tactic_id}";'
        MitreDB.execute_query(query)

    # Remove all selected techniques and their sub-categories using a single SQL query
    technique_pattern = re.compile(r'.*TA\d+\.T\d+\.xxx|.*TA\d+\.T\d+$')    # (with sub) ASC.8.TA0001.T1078.xxx or (without sub) ASC.8.TA0001.T1000
    techniques = list(filter(technique_pattern.match, categories))
    for t in techniques:
        try:
            alert_id = re.search(r'.*(?=.TA.*)', t).group()  # ASC.8
            tactic_id = re.search(r'TA\d+', t).group()  # TA0001
            technique_id = re.search(r'T\d+', t).group()  # T1078
        except Exception as e:
            print("Error trying to identify elements got from html: ", e)
            continue

        query = f'DELETE FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert_id}" AND ta_id LIKE "{tactic_id}" AND t_id LIKE "{technique_id}";'
        MitreDB.execute_query(query)

    # Only sub-techniques remaining
    for sub in categories:  # ASC.8.TA0001.T1078.001 or AAD.1.TA0001.T1078.void
        try:
            alert_id = re.search(r'.*(?=.TA.*)', sub).group()               # ASC.8
            tactic_id = re.search(r'TA\d+', sub).group()                    # TA0001
            technique_id = re.search(r'T\d+', sub).group()                  # T1078
            sub_technique_id = re.search(rf'(?<=\.)\d+$|(?<=\.){OTHER_SUB_TECHNIQUE}$', sub).group()       # 001 or (eg) void
        except Exception as e:
            print("Error trying to identify elements got from html: ", e)
            continue

        query = f'DELETE FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert_id}" AND ta_id LIKE "{tactic_id}" AND t_id LIKE "{technique_id}" AND subt_id LIKE "{sub_technique_id}";'
        MitreDB.execute_query(query)



@app.route('/ModifyTools', methods=['GET', 'POST'])
def modify_tools():
    """
    Display and manage tools existing in database
    :return: ModifyTools.html
    """
    conn_info = get_config()
    try:
        MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])
    except Exception as e:
        return render_template('Error.html', info=f'Error while connection to DB: {str(conn_info) + " ->" + str(e)}')

    add = request.form.get('add')                       # Bool to check add button
    insert_error = None
    tool_to_insert = request.form.getlist('add_tool')   # Get data to add

    delete = request.form.get('delete')                         # Bool to check delete button
    delete_error = None
    tools_to_remove = request.form.getlist('tools_to_remove')   # Get data to delete

    modify = request.form.get('modify')                         # Bool to check modify button

    if delete and len(tools_to_remove) < 0:
        delete_error = "Select almost a tool to delete"         # Bad user behaviour

    if delete and len(tools_to_remove) > 0:                     # Remove selected tools
        for t in tools_to_remove:
            query = f'DELETE FROM {TOOL_TABLE} WHERE id = {t};'
            MitreDB.execute_query(query)

    if add and len(tool_to_insert):                               # Add tool
        id = tool_to_insert[0]
        name = tool_to_insert[1]
        type = tool_to_insert[2]
        query = f'INSERT INTO {TOOL_TABLE} VALUES ({id},"{name}", "{type}");'
        insert_error = MitreDB.execute_query(query)

    if modify:
        modify_error = "Select almost an element to modify"             # Error by default
        names_to_modify = request.form.listvalues()
        for n in names_to_modify.mapping:                                   # (?) Name of sub-element of the dict (found with debugger)
            nn = re.search(r'(?<=new_name_for_)\d+', n)
            nt = re.search(r'(?<=new_type_for_)\d+', n)

            if nn is not None:
                modify_error = None  # No bad user behaviour
                tool_id = nn.group()
                new_name = request.form.get(str(n))
                if new_name is not None:
                    query = f'UPDATE {TOOL_TABLE} SET name = "{new_name}" WHERE id = {tool_id};'
                    MitreDB.execute_query(query)
                else:
                    print(f'Error reading new name for tool {tool_id} on modify_tool web page')
                    continue

            if nt is not None:
                modify_error = None  # No bad user behaviour
                tool_id = nt.group()
                new_type = request.form.get(str(n))  # get value for the field new_name_for_x
                if new_type is not None:
                    query = f'UPDATE {TOOL_TABLE} SET type = "{new_type}" WHERE id = {tool_id};'
                    MitreDB.execute_query(query)
                else:
                    print(f'Error reading new type for tool {tool_id} on modify_tool web page')
                    continue
    else:
        modify_error = None

    tools = []
    for t in MitreDB.get_db_tools():
        tools.append(t)

    return render_template("ModifyTools.html", tools=tools, modify_error=modify_error, delete_error=delete_error, insert_error="Error occurred: " + str(insert_error) if insert_error else None)


@app.route('/ModifyAlerts', methods=['POST'])
def modify_alerts():
    """
        Display and manage alerts existing in database
        :return: ModifyAlerts.html
    """
    conn_info = get_config()
    try:
        MitreDB = MitreTTPDatabase(conn_info['user'], conn_info['password'], conn_info['ip'], conn_info['schema'])
    except Exception as e:
        return render_template('Error.html', info=f'Error while connection to DB: {str(conn_info) + " ->" + str(e)}')

    errors = ""

    if request.form.get('add'):
        alert_id = request.form.get('id')
        tool = request.form.get('tool')
        description = request.form.get('description')
        miss_num = request.form.get('miss_num')
        query = f'INSERT INTO {CUSTOM_ALERT_TABLE} VALUES ("{alert_id}", {tool}, {miss_num}, "{description}");'
        if (res := MitreDB.execute_query(query)) is not None:
            errors += str(res) + '\n'

    if request.form.get('delete'):
        alert_to_delete = request.form.getlist('alert_id')
        for alert in alert_to_delete:
            query = f'DELETE FROM {CUSTOM_ALERT_TABLE} WHERE id LIKE "{alert}";'
            if (res := MitreDB.execute_query(query)) is not None:
                errors += str(res) + '\n'


    if request.form.get('modify'):
        alerts = request.form.getlist('alert_id')
        for alert in alerts:
            new_tool_number = request.form.get(f'{alert}.new_number')
            new_description = request.form.get(f'{alert}.new_description')

            if new_description is None:
                new_description = ""

            query = f'UPDATE {CUSTOM_ALERT_TABLE} SET tool = {new_tool_number}, description = "{new_description}" WHERE id LIKE "{alert}";'
            if (res := MitreDB.execute_query(query)) is not None:
                errors += str(res) + '\n'

    return render_template('ModifyAlerts.html', title='MODIFY ALERTS', alerts=MitreDB.get_db_alerts(), errors=errors)

# Api used to get the mitre category matched to an alert if any
@app.route('/api', methods=['POST'])
def get_matches():
    """
    Function to call api
    :return: json with found categories
    """
    if not request.is_json:
        print("POST data received not json type")
        return []
    if 'error' in (matches := mitrettp_api.get_mitre_category(request.json)):
        return matches, 500
    else:
        return matches


@app.template_filter('sanitize')
def sanitize(string: str):
    return re.sub("[^0-9a-zA-Z]+", "-", string)
# app.jinja_env.filters['reverse'] = sanitize


if __name__ == '__main__':
    app.run()
    # displayable_data()

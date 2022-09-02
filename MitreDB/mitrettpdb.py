from MitreCategories import *
from Alert import Alert
from Tool import Tool
from treelib import Tree, Node
from mysqlx import errorcode, errors
import mysql.connector
import yaml

SCHEMA = 'mitrettp'
# # Database parameters
# USER = "root"
# PASSWORD = "Pol789qas!"
# IP = "10.0.0.21"
# SCHEMA = "mitrettp"

# Tables in mitrettp schema
TACTIC_TABLE = "tactic"
TECHNIQUE_TABLE = "technique"
SUB_TECHNIQUE_TABLE = "sub_technique"
RELATION_TABLE = "relation_tactic_technique"
CUSTOM_ALERT_TABLE = "custom_alert"
CUSTOM_RULE_TABLE = "custom_rule"
TOOL_TABLE = "tool"

# !!! NB. CONTROL_VAIABLE is used as string also in TRIGGER in mitrettp.custom_rule !!!
OTHER_SUB_TECHNIQUE = "Other"   # Constant used to select technique without selecting sub-techniques in mitrettp.custom_rule table
CONROL_VARIABLE = "void"        # Constant used to manage technique without sub-techniques in mitrettp.custom_rule table

# FILE1 = "C:\\Users\\y.riccardo.gobbo\\Desktop\\Yarix files\\File json\\DB_rules.json"  # Da sostituire con il percorso all'interno del server di The Hive
# TOOL = 0


class MitreTTPDatabase:
    def __init__(self, user: str, password: str, ip: str, schema: str):
        """
        Create a object that can use mitrettp database
        :param user: User to login to MySQL
        :param password: Password to login to MySQL
        :param ip: IP where DB is hosted
        :param schema: Mitre schema
        """
        try:
            # print("Connecting to database..")
            self._db_connection = mysql.connector.connect(user=user, password=password, host=ip,database=schema)  # Try to connect to DB, if pass we already are into the schema

        except mysql.connector.Error as err:  # Check possible errors
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
            else:
                print(err)
            raise err
        self._cursor = self._db_connection.cursor()


    def update_config(self, path : str = "/home/thehive/utils/", schema : str = "mitrettp" ):
        """
        Function to update the db file configuration of a MitreTTPDatabase object
        :param path: path to the file containing the DB configurations
        :param schema: Schema where are stored Mitre, alerts and alerts-mitre matches tables
        :return: None
        """
        path = ""                                                                           # TODO Temporary path
        with open(path + "conf.yml") as yml_conf:
            mysql_conf = yaml.load(yml_conf, Loader=yaml.FullLoader)['mysql']

        IP = mysql_conf['IP']
        SCHEMA = schema
        USER = mysql_conf['usr']
        PASSWORD = mysql_conf['psw']


    def fill_mitre_tables(self) -> str:
        """
        Populate the DB with updated data got from Mitre repository
        :return str error: String containing the details of occured errors
        """
        errors = ""
        tactics = get_updated_tactics()
        for t in tactics:
            query = f'UPDATE {TACTIC_TABLE} SET name="{t.get_name()}", link="{t.get_link()}" WHERE id = "{t.get_id()}";'
            if (e := self.execute_query(query)) is not None:
                errors += str(e) + '\n'
                # print("Error:  ", e)
                continue

            query = f'INSERT INTO {TACTIC_TABLE} VALUES ("{t.get_id()}","{t.get_name()}","{t.get_link()}");'
            if (e := self.execute_query(query)) is not None:
                errors += str(e) + '\n'
                # print("Error:  ", e)
                continue

        # Insert techniques second. In this way both sub_techniques and relation_tactic_techniques tables can be populated
        # print("Inserting techniques and tactics-techniques relations..")
        techniques = get_updated_techniques()
        query_relation_table = []
        for te in techniques:
            # Updating or adding entries to tactic table
            query = f'UPDATE {TECHNIQUE_TABLE} SET name="{te.get_name()}", link="{te.get_link()}" WHERE id = "{te.get_id()}";'
            if (e := self.execute_query(query)) is not None:
                errors += str(e) + '\n'
                # print("Error:  ", te.info())
                continue

            query = f'INSERT INTO {TECHNIQUE_TABLE} VALUES ("{te.get_id()}","{te.get_name()}","{te.get_link()}");'  # Can throw ad exception (duplicate entry)
            if (e := self.execute_query(query)) is not None:
                errors += str(e) + '\n'
                # print("Error:  ", te.info())
                continue


            if len(te.get_tactic()) < 1:
                raise NameError(f"Techniques have to belog at least to one tactic\nError Error or warning due    {te.info()}")

            query_relation_table.clear()        # Clear old tactics of previous technique
            for ta in te.get_tactic():
                ta_id = find_id(ta, tactics)     # Get the id of the tactic in which the technique can be found
                query = f'INSERT INTO {RELATION_TABLE} VALUES ("{ta_id}","{te.get_id()}");'
                if (e := self.execute_query(query)) is not None:
                    errors += str(e) + '\n'
                    # print("Error:  ", ta.info())
                    continue

        # Insert sub-techniques third. In this order there already are foreign keys in techniques table
        sub_techniques = get_updated_sub_techniques()
        for st in sub_techniques:
            # try:
            technique_id = st.get_id().rsplit(".")[0]
            sub_technique_id = st.get_id().rsplit(".")[1]

            query = f'UPDATE {SUB_TECHNIQUE_TABLE} SET name="{st.get_name()}", link="{st.get_link()}" WHERE id = "{technique_id}" AND sub_id = "{sub_technique_id}";'
            if (e := self.execute_query(query)) is not None:
                errors += str(e) + '\n'
                # print("Error:  ", e)
                continue

            query = f'INSERT INTO {SUB_TECHNIQUE_TABLE} VALUES ("{technique_id}","{sub_technique_id}","{st.get_name()}","{st.get_link()}");'
            if (e := self.execute_query(query)) is not None:
                errors += str(e) + '\n'
                # print("Error:  ", e)
                continue

        print(f'Mitre tables filled')
        return errors


    def fill_custom_alert_table(self, file: str, tool: int):
        """ Method to populate the table containing custom rules with QR rules\n
            The structure of the file must be an array of objects and every object should contain 'code' and 'description' fields\n
        :param str file : path to json with alerts
        :param str tool : tool associated to file's alerts"""
        try:
            # print("Opening file..\n")
            file_input = open(file, "r")
        except Exception as e:
            print("Error tring open the file: ", e)
            return

        # print("Opened\n")

        # print("Analyzing..\n")
        # ----- QR rules ------
        dictionary = json.load(file_input)                          # Read file
        for d in dictionary:
            id = d['code']                                          # e.g. AV.1
            try:
                description = d['description']                      # Description is optional
                description = description.replace("\"", "\\\"")     # Replace " with \" to make query readable
            except Exception as err:
                pass
            finally:
                description = ""

            try:
                query_update = f'UPDATE {CUSTOM_ALERT_TABLE} SET description = "{description}" WHERE id = "{id}";'          # Try update
                query_insert = f'INSERT INTO {CUSTOM_ALERT_TABLE} VALUES ("{id}", {tool}, 1, "{description}");'             # Try insertion
                self.execute_query(query_update)
                self.execute_query(query_insert)
                # self._db_connection.commit()
            except Exception as e:
                if "duplicate entry" not in str(e).lower():  # Check for other errors than duplicate entry
                    print("Error occured: ", e)
        # print("Done.")


    def get_db_tactics(self, ta_id : str = '%') -> list[MitreElement]:
        """ Return an array of MitreElement objects rappresenting tactics actually in the databse
        :param str ta_id: (optional) tactic id, useful to create a MitreElement object"""
        query = f'SELECT * FROM {TACTIC_TABLE} WHERE id LIKE "{ta_id + "%"}" ORDER BY name ASC;'
        row = self.execute_query(query)

        tactics = []
        for r in row:
            t_id = r[0]
            name = r[1]
            link = r[2]
            tactics.append(MitreElement(t_id, name, 0, link))
        return tactics


    def get_db_techniques(self, tactic_id: str = None, tech_id: str = '%') -> list[MitreElement]:
        """ Return an array of MitreElement objects rappresenting techniques actually in the databse.\n
        :param str tactic_id : (optional) tactic id. Useful to obtain all techniques of a specified tactic
        :param str tech_id : (optional) technique id. Useful to create a complete MitreElement object"""

        # Get all entries from table
        if tactic_id is None:
            query = f'SELECT * FROM {TECHNIQUE_TABLE} WHERE id LIKE "{tech_id + "%"}" ORDER BY name ASC;'
        else:
            # Select all techniques of a specific tactic. Then select a specific technique is required by parameter
            query_for_ids = f'SELECT t_id FROM {RELATION_TABLE} WHERE ta_id LIKE "{tactic_id + "%"}"'
            query = f'SELECT * FROM {TECHNIQUE_TABLE} JOIN ({query_for_ids}) AS tech_ids ON id = tech_ids.t_id WHERE id LIKE "{tech_id + "%"}" ORDER BY name ASC;'

        rows = self.execute_query(query)

        techniques = []
        for r in rows:
            t_id = r[0]  # Technique id
            name = r[1]
            link = r[2]
            tactics_names = []

            # Get all tactics name associated to a technique
            tactics_names_query = f'SELECT name FROM ( SELECT * FROM {RELATION_TABLE} WHERE t_id = "{t_id}") AS techn JOIN {TACTIC_TABLE} ON ta_id = id;'
            res = self.execute_query(tactics_names_query)
            # Save names in a list
            for r in res:
                tactics_names.append(r[0])

            techniques.append(MitreElement(t_id, name, 1, link, tactics_names))

        return techniques


    def get_db_subtechniques(self, tech_id: str = '%', subt_id: str = '%') -> list[MitreElement]:
        """ Return an array of MitreElement objects rappresenting sub-techniques  actually in the databse.
        :param str subt_id : (optional) sub-technique id. Useful to create a complete MitreElement object"""
        # Get all entries from table
        query = f'SELECT * FROM {SUB_TECHNIQUE_TABLE} WHERE id LIKE "{tech_id + "%"}" AND sub_id LIKE "{subt_id + "%"}" ORDER BY name ASC;'
        rows = self.execute_query(query)

        # Analyze each entry
        sub_techniques = []
        tactics = []

        for r in rows:
            t_id = r[0]                 # Technique id
            st_id = r[1]                # Sub-technique id
            name = r[2]
            link = r[3]
            tactics_names = []

            # Get the name of the
            # Example of query =   SELECT tactic.name          FROM ( SELECT * FROM sub_technique        JOIN relation_tactic_technique ON id = t_id HAVING id="T1037" AND sub_id="001") AS relations JOIN tactic       ON ta_id = tactic.id;
            tactics_names_query = f'SELECT {TACTIC_TABLE}.name FROM (SELECT * FROM {SUB_TECHNIQUE_TABLE} JOIN {RELATION_TABLE} ON id = t_id HAVING id="{t_id}" AND sub_id="{st_id}") AS relations JOIN {TACTIC_TABLE} ON ta_id = {TACTIC_TABLE}.id;'

            res = self.execute_query(tactics_names_query)
            # Save names in a list
            for r in res:
                tactics_names.append(r[0])

            sub_techniques.append(MitreElement(".".join([t_id, st_id]), name, 2, link, tactics_names))

        return sub_techniques


    def get_db_alerts(self, alert_id: str = '%',
                      tool: int = -1,
                      miss_num: int = -1,
                      order_by: enumerate(["id", "tool", "miss_num", "description"]) = 'id',
                      mode: enumerate(["ASC", "DESC"]) = 'ASC') -> list[Alert]:
        """ Get a list of Alert objects containing all alerts that are in the custom_alert table\n
        :param str order_by : (optional) "id", "type", "tool", "miss_num", "description"
        :param str mode     : (optional) "ASC", "DESC"
        :param str alert_id : (optional) select a specific id
        :param int tool     : (optional) select all alarms of a specific tool
        :param int miss_num : (optional) select all alarms with a specific num of search misses by the api
        :return: list[Alert] """

        # With default values, don't filter for that field
        if tool == -1:
            tool = '%'
        if miss_num == -1:
            miss_num = '%'

        # if query is None:
        query = f'SELECT {CUSTOM_ALERT_TABLE}.id, tool, name, type, miss_num, description FROM {CUSTOM_ALERT_TABLE} JOIN {TOOL_TABLE} on tool = {TOOL_TABLE}.id WHERE {CUSTOM_ALERT_TABLE}.id LIKE "{alert_id}" AND tool LIKE "{tool}" AND miss_num LIKE "{miss_num}" ORDER BY {CUSTOM_ALERT_TABLE}.{order_by} {mode};'

        row = self.execute_query(query)
        alerts = []
        for r in row:
            alert_id = r[0]
            tool = Tool(r[1], r[2], r[3])                               # The function get_db_tools isn't used here to reduce loaging web page time from 10s to 2s
            miss_num = r[4]
            description = r[5]
            alerts.append(Alert(alert_id, tool, description, miss_num))

        return alerts


    def get_db_rules(self) -> list[Tree]:
        """
        Return a list of Tree objects rappresenting all matches Alert-MitreElement that are in custom_rule. All trees' roots have an
        Alert object in data field meanwhile children have MitreElement object.
        :return: list[Tree]
        """
        rules = []

        # query = f'SELECT alert_id, tool, description FROM {CUSTOM_RULE_TABLE} JOIN {CUSTOM_ALERT_TABLE} ON alert_id = id ORDER BY alert_id ASC;'   # Getting alert_ids and their description
        query = f'SELECT DISTINCT alert_id, tool, description FROM {CUSTOM_RULE_TABLE} JOIN {CUSTOM_ALERT_TABLE} ON alert_id = id ORDER BY alert_id ASC;'   # Getting alert_ids and their description
        rows = self.execute_query(query)

        for alert in rows:                                                                                                      # For each alert
            try:
                alert_id = alert[0]
                tool = self.get_db_tools(alert[1])                                                                                    # Use the function to get a Tool object. NB It returns a list
                alert_description = alert[2]

                alert_tree = Tree()                                                                                             # Creation of a tree
                node_id = str(alert_id)                                                                                         # Set node's id
                alert_tree.create_node(None, node_id, None, Alert(alert_id, tool.pop(), alert_description))                           # Creation of the root

                query = f'SELECT DISTINCT ta_id FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert_id}" ORDER BY ta_id ASC;'  # Get all tactics matched to the specific alert
                tactics = self.execute_query(query)                                                                             # Create a list of MitreElement object
                for ta in tactics:                                                                                              # Repeat for every sub categories
                    parent_node_id = str(alert_id)                                                                              # Set parent's node's id
                    tactic_id = ta[0]
                    tactic = self.get_db_tactics(tactic_id)                                                                          # Create a MitreElement

                    node_id = f'{alert_id}.{tactic_id}'                                                                         # Update node's id
                    alert_tree.create_node(None, node_id, parent_node_id, tactic[0])
                    parent_node_id = f'{alert_id}.{tactic_id}'                                                                  # Update parent's node's id

                    query = f'SELECT DISTINCT t_id FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert_id}" AND ta_id LIKE "{tactic_id}" ORDER BY t_id ASC;'
                    techniques = self.execute_query(query)
                    for te in techniques:
                        technique_id = te[0]
                        technique = self.get_db_techniques(tech_id=technique_id) # Get Mitre element corresponding to technique_id

                        node_id = f'{alert_id}.{tactic_id}.{technique_id}'
                        alert_tree.create_node(None, node_id, parent_node_id, technique[0])
                        parent_node_id = f'{alert_id}.{tactic_id}.{technique_id}'

                        query = f'SELECT DISTINCT subt_id FROM {CUSTOM_RULE_TABLE} WHERE alert_id LIKE "{alert_id}" AND ta_id LIKE "{tactic_id}" AND t_id LIKE "{technique_id}" ORDER BY subt_id ASC;'
                        sub_techniques = self.execute_query(query)
                        for subt in sub_techniques:
                            subt_id = subt[0]
                            node_id = f'{alert_id}.{tactic_id}.{technique_id}.{subt_id}'

                            if OTHER_SUB_TECHNIQUE in subt:
                                sub_technique = [MitreElement(OTHER_SUB_TECHNIQUE, OTHER_SUB_TECHNIQUE, 2, None, None)]
                            elif CONROL_VARIABLE in subt:
                                continue
                            else:
                                sub_technique = self.get_db_subtechniques(tech_id=technique_id, subt_id=subt_id)

                            alert_tree.create_node(None, node_id, parent_node_id, sub_technique[0])
                        parent_node_id = f'{alert_id}.{tactic_id}'
            except Exception as e:
                print("Exception occured: ", str(e))
                continue
            rules.append(alert_tree)
        return rules


    def get_db_data(self) -> list[Tree]:
        """
        Return a list of Tree objects where nodes have a MitreElement in data field. \n
            In trees'roots there are MitreElement object rappresenting tactics, then children nodes rappresent techniques, then children node rappresent sub-techniques.
        :return: list[Tree]
        """

        all_db_data = []

        query = f'SELECT * FROM {TACTIC_TABLE};'
        tactics_data = self.execute_query(query)

        for ta in tactics_data:
            mitre_tree = Tree()
            if CONROL_VARIABLE in ta:
                continue
            try:
                tactic_id = ta[0]
                tactic_name = ta[1]
                tactic_link = ta[2]
                mitre_tree.create_node(None, tactic_id, None, MitreElement(tactic_id, tactic_name, 0, tactic_link))

                query = f'SELECT {TECHNIQUE_TABLE}.id, {TECHNIQUE_TABLE}.name, {TECHNIQUE_TABLE}.link FROM ( SELECT * FROM {TACTIC_TABLE} JOIN {RELATION_TABLE} ON id=ta_id WHERE ta_id LIKE "{tactic_id}") AS rel JOIN {TECHNIQUE_TABLE} ON t_id = {TECHNIQUE_TABLE}.id;'
                techniques_data = self.execute_query(query)

                for t in techniques_data:
                    parent_node_id = tactic_id
                    technique_id = t[0]
                    technique_name = t[1]
                    technique_link = t[2]

                    node_id = f'{tactic_id}.{technique_id}'
                    mitre_tree.create_node(None, node_id, parent_node_id, MitreElement(technique_id, technique_name, 1, technique_link))
                    parent_node_id = f'{tactic_id}.{technique_id}'

                    query = f'SELECT {SUB_TECHNIQUE_TABLE}.id, {SUB_TECHNIQUE_TABLE}.sub_id, {SUB_TECHNIQUE_TABLE}.name, {SUB_TECHNIQUE_TABLE}.link FROM {SUB_TECHNIQUE_TABLE} join {TECHNIQUE_TABLE} on {SUB_TECHNIQUE_TABLE}.id = {TECHNIQUE_TABLE}.id where {TECHNIQUE_TABLE}.id LIKE "{technique_id}";'
                    sub_t_data = self.execute_query(query)
                    for s in sub_t_data:
                        s_id = s[0]
                        s_sub_id = s[1]
                        s_name = s[2]
                        s_link = s[3]

                        node_id = f'{tactic_id}.{technique_id}.{".".join([s_id, s_sub_id])}'
                        mitre_tree.create_node(None, node_id, parent_node_id, MitreElement(s_id + '.' + s_sub_id, s_name, 2, s_link))

            except Exception as e:
                print("Error while creating tree node: ", e)
                continue

            all_db_data.append(mitre_tree)

        return all_db_data


    def get_db_tools(self, id: int = -1, name: str = '%', type: str = '%') -> list[Tool]:
        """
        Function to obtain all tool in the tool table in mitrettp DB
        :return: list[Tool]
        """

        if id == -1:
            id = '%'

        tools = []
        query = f'SELECT id, name, type FROM {TOOL_TABLE} WHERE id LIKE "{id}" AND name LIKE "{name}" AND type LIKE "{type}";'
        rows = self.execute_query(query)
        for r in rows:
            id = r[0]
            name = r[1]
            type = r[2]
            try:
                tools.append(Tool(id, name, type))
            except Exception as e:
                print("Error creating tool: ", e)

        #self._db_connection.close()
        return tools


    #  --------------------- Class utilities for main functions ---------------------
    def execute_query(self, query : str = None):
        if self._db_connection is None or self._cursor is None or query is None:
            print(f'Issue occured with eigther connection to DB or cursor or query:\nConnection: {self._db_connection}\nCursor: {self._cursor}\nQuery:{query}')
            return errors.Error
        try:
            self._cursor.execute(query)
            if 'SELECT' in query.split()[0].upper():
                return self._cursor.fetchall()
            elif 'INSERT' or 'UPDATE' or 'DELETE' in query.split()[0].upper():
                self._db_connection.commit()
        except Exception as e:
            if 'duplicate entry' not in str(e).lower():
                print("Error: ", e)
            return e
        return None


# ---------------------- UTILITIES ----------------------

def find_id(tactic_name, analyzed_categories: List[MitreElement]) -> str:
    """ Find the id (string) of a given tactic's name if present in analyzed_categories, that is a list of MitreElement """
    for elem in analyzed_categories:
        elem_name = elem.get_name()                                 # Lateral Movement
        if to_phase_name(elem_name) == tactic_name:
            return elem.get_id()
    return None

def find_name(tactic_id, analyzed_categories: List[MitreElement]) -> str:
    """ Find the name of a given tactic's id if present in analyzed_categories, that is a list of MitreElement """
    for elem in analyzed_categories:
        if elem.get_id() == tactic_id:
            return elem.get_name()
    return None

def to_phase_name(name: str) -> str:
    """
    Function to obtain phase name of a tactic
    :param name: Normal name of the tactic (e.g. Initial Access)
    :return: standard Mitre name (e.g. initial-access)
    """
    return '-'.join(name.lower().split())

def get_config() -> dict:
    """
    Obtain information needed to connect to MySQL database
    :return: dict with 'ip', 'schema', 'user', 'password' or Exception if some issues occured while reading conf file
    """
    path = ""                                                                           # TODO Temporary path
    try:
        with open(path + "conf.yml") as yml_conf:
            mysql_conf = yaml.load(yml_conf, Loader=yaml.FullLoader)['mysql']
    except Exception as e:
        return e

    return {
        'ip' : mysql_conf['IP'],
        'schema' : SCHEMA,
        'user' : mysql_conf['usr'],
        'password' : mysql_conf['psw'],
    }

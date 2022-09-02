import json
import urllib.request
from typing import List

# Mitre repository
URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class MitreElement():
    """ Class rappresenting a Mitre category \n
        :param str cat_id       : The id of the object
        :param str name         : The name of the object
        :param str mitre_type   : The type of the object (0 tactic, 1 technique, 2 sub-technique
        :param str link         : Link to the page of Mitre website
        :param list str tactic   : List of the tactic associated to the object (if any)
    """
    # Type: 0 - tactics, 1 - techniques, 2 - sub-techniques
    def __init__(self, cat_id : str, name : str, mitre_type : int, link  : str, tactics : List[str] = None ):
        self._id = cat_id
        self._name = name
        self._type = mitre_type
        self._link = link
        self._tactics = tactics

    def info(self) -> str:
        """ Return a string with <id> - <name> - <type> - <tactics> - <link> of the MitreElement object"""
        return self._id + " - " + self._name + " - " + str(self._type) + " - " + str(self._tactics) + " - " + self._link

    def get_id(self) -> str:
        """ Return the id of the MitreElement object """
        return self._id

    def get_name(self) -> str:
        """ Return the name of the MitreElement object """
        return self._name

    def get_type(self) -> int:
        """ Return the type of the MitreElement object """
        return self._type

    def get_tactic(self) -> list[str]:
        """ Return the tactics'names of the MitreElement object """
        return self._tactics

    def get_link(self) -> str:
        """ Return the link of the MitreElement object """
        return self._link

def get_mitre_from_repository() -> list[MitreElement]:
    """ Return an array filled with MitreElement objects """

    dictionary = json.loads(urllib.request.urlopen(URL).read().decode())

    categories = []

    for c in dictionary['objects']:
        try:
            tactic_name = c['type']
            if tactic_name == "x-mitre-tactic":
                ta_id = c['external_references'][0]['external_id']
                # ta_name = c['x_mitre_shortname']
                ta_name = c['name']                                     # Fornisce un nome del tipo "Lateral Movement" non "lateral-movement"
                ta_type = 0
                ta_link = c['external_references'][0]['url']

                categories.append(MitreElement(ta_id, ta_name, ta_type, ta_link))
        except KeyError as err:
            pass

    # Adding only the objects that have [id, name, sub-technique, link, tactic]
    for i in dictionary['objects']:
        if "attack-pattern" not in i['type']:
            continue
        te_tactic = []
        try:
            te_id = i['external_references'][0]['external_id']
            te_name = i['name']
            te_type = 1 if not i['x_mitre_is_subtechnique'] else 2
            te_link = i['external_references'][0]['url']

            if te_type != 0:
                for t in i['kill_chain_phases']:        # One technique can belongs to many tactics
                    te_tactic.append(t['phase_name'])    # Obtain all tactics of the specific technique

            categories.append(MitreElement(te_id, te_name, te_type, te_link, te_tactic))

        except KeyError as err:
            pass

    return categories


def get_updated_tactics() -> list[MitreElement]:
    """ Return an array with all updated tactics """
    tactics_to_return = []
    all_categories = get_mitre_from_repository()

    for m in all_categories:
        if m.get_type() == 0:
            tactics_to_return.append(m)
    return tactics_to_return


def get_updated_techniques() -> list[MitreElement]:
    """ Return an array with all updated techniques """

    techniques_to_return = []
    all_categories = get_mitre_from_repository()

    for m in all_categories:
        if m.get_type() == 1:
            techniques_to_return.append(m)
    return techniques_to_return


def get_updated_sub_techniques() -> list[MitreElement]:
    """ Return an array with all updated sub-techniques """

    sub_techniques_to_return = []
    all_categories = get_mitre_from_repository()

    for m in all_categories:
        if m.get_type() == 2:
            sub_techniques_to_return.append(m)
    return sub_techniques_to_return


# if __name__ == "__main__":
#     for c in get_mitre_from_repository():
#         print(c.info())

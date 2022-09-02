from Tool import Tool

class Alert:
    """ Class rappresenting an alert of a tool \n
        :param str id           : The id of the object
        :param int tool         : Tool associated to a specific rule ("QRadar", "Cynet", "DarkTrace", "CrowdStrike", "PaCortex")
        :param str description  : Description of the alarm
        :param str miss_num     : Number of require attempts for a rule without association to Mitre
    """
    # Type: 0 - tactics, 1 - techniques, 2 - sub-techniques
    def __init__(self, id : str, tool : Tool, description : str,  miss_num : int = 0):
        self._id = id
        self._tool = tool
        self._miss_num = miss_num
        self._description = description

    def get_id(self) -> str:
        return self._id

    def get_tool(self) -> Tool:
        return self._tool

    def get_description(self) -> str:
        return self._description

    def get_miss_num(self) -> int:
        return self._miss_num



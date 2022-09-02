class Tool:
    """ Class rappresenting a tool \n
        :param str id           : The id of the object
        :param int name         : Name of the tool
        :param str type         : Type of the object (Siem, Netmon, XDR, ...)
    """
    # Type: 0 - tactics, 1 - techniques, 2 - sub-techniques
    def __init__(self, id : int, name : str, type : str):
        self._id = id
        self._type = type
        self._name = name

    def __str__(self):
        return f'id: {self._id} - name: {self._name} - type: {self._type}'

    def get_id(self) -> str:
        return self._id

    def get_name(self) -> str:
        return self._name

    def get_type(self) -> str:
        return self._type



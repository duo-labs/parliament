class Finding:
    """ Class for storing findings """

    issue = ""
    detail = ""
    location = {}
    severity = ""
    title = ""
    description = ""
    ignore_locations = {}

    def __init__(self, issue, detail, location):
        self.issue = issue
        self.detail = detail
        self.location = location

    def __repr__(self):
        """ Return a string for printing """
        return "{} - {} - {}".format(self.issue, self.detail, self.location)

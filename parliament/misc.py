import jsoncfg


def make_simple_list(v):
    """
    If the object is not a list already, it converts it to one
    Examples:
    [1, 2, 3] -> [1, 2, 3]
    [1] -> [1]
    1 -> [1]

    This is a very simple function to listify a single object as required.
    """
    if not isinstance(v, list):
        return [v]
    return v


def make_location_list(v):
    """
    Create a list of location identifiers for a file. This is either going to be
    a single location identifier that is being made into a list, or a list of them
    which will be returned automatically.

    If the object is not a list already, it converts it to one
    Examples:
    [{line: 1, column: 1}, {line: 15, column: 3}] -> [{line: 1, column: 1}, {line: 15, column: 3}]
    [{line: 1, column: 1}] -> [{line: 1, column: 1}]
    {line: 1, column: 1} -> [{line: 1, column: 1}]
    """
    if not jsoncfg.node_is_array(v):
        if jsoncfg.node_is_scalar(v):
            location = jsoncfg.node_location(v)
            line = location.line
            column = location.column
        elif jsoncfg.node_exists(v):
            line = v.line
            column = v.column
        else:
            return []

        a = jsoncfg.config_classes.ConfigJSONArray(line, column)
        a._append(v)
        return a
    return v


class ACCESS_DECISION:
    IMPLICIT_DENY = 0
    EXPLICIT_DENY = 1
    EXPLICIT_ALLOW = 2

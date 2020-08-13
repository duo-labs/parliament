import jsoncfg


def make_list(v):
    """
    If the object is not a list already, it converts it to one
    Examples:
    [1, 2, 3] -> [1, 2, 3]
    [1] -> [1]
    1 -> [1]
    """
    if not jsoncfg.node_is_array(v):
        if jsoncfg.node_is_scalar(v):
            location = jsoncfg.node_location(v)
            line = location.line
            column = location.column
        else:
            line = v.line
            column = v.column

        a = jsoncfg.config_classes.ConfigJSONArray(line, column)
        a._append(v)
        return a
    return v


class ACCESS_DECISION:
    IMPLICIT_DENY = 0
    EXPLICIT_DENY = 1
    EXPLICIT_ALLOW = 2

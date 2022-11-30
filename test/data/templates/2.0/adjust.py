def adjust(config, mapping):
    """
    Set the test_adjust option
    """

    print("Adjusting configuration")

    for component in config:
        if "test_adjust" in config[component]:
            config[component]["test_adjust"] = "adjusted 2.0"

    return

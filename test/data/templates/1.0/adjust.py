def adjust(config, mapping) -> None:
    """
    Set the test_adjust option
    """

    print("Adjusting configuration")

    for component in config:
        if "test_adjust" in config[component]:
            config[component]["test_adjust"] = "adjusted 1.0"

    return

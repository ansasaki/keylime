#!/usr/bin/env python3

import argparse
import configparser
import importlib.util
import json
import os
import re
import shutil
import sys
from functools import cmp_to_key

from jinja2 import Template

"""
 This script parses the content of a configuration file and use the data to
 replace the values in templates to generate new configuration files.  The
 process is controlled by the "mapping" dictionary, provided through a JSON
 file.

 This dictionary maps the name of the new option to a dictionary with the info
 from the old configuration file format.

 The dictionary has the following fields:
 * "version": The mapping version. Should match the target configuration version
 number
 * "components": A dictionary which keys are the components for which the
 configuration files should be generated. The keys in the "components"
 dictionary should match the template file names without the extension (e.g.
 for the agent component, the key should be "agent" and the template file name
 should be "agent.j2").
 * "subcomponents": A dictionary which maps sections names without a version
 number to the main section name which has the version number. The idea is that
 only the main section contains the version number for the entire file (e.g. the
 "verifier" section in the "verifier.conf" file) which will be inherited by the
 subcomponents.

 For each component in the "components" dictionary, the value is a dictionary
 which keys are the option names in the new configuration files and the value is
 a dictionary with the information used to find the data in the old
 configuration file. For each option name the value is a dictionary with the
 following fields:

 * "section": The section from the old configuration file
 * "option": The name of the option in the old configuration file
 * "default" The default value to use in case the option is missing in the
 old configuration file

 All values are treated as strings.

 An example could be:

 {
     "version": "1.0",
     "components": {
         "a_component": {
             "some_option": {
                 "section": "some_section",
                 "option" : "some_old_option_name",
                 "default": "default",
             },
             another_option: {
                 "section": "another_section",
                 "option" : "another_old_option_name",
                 "default": "default_value",
             }
         },
         "another_component": {
             "an_option": {
                 "section": "some_section",
                 "option" : "some_old_option_name",
                 "default": "default",
             },
             "another_option": {
                 "section": "another_section",
                 "option" : "another_old_option_name",
                 "default": "default_value",
             }
         }
     },
     "subcomponents" {
        "another_section": "some_section"
     }
 }

 Check "scripts/templates/2.0/mapping.json" file for an example.

 The idea is to provide new templates, mapping, and adjust script for new
 versions of the configuration, allowing the user to easily convert from a
 version of the configuration file to the next.
"""

COMPONENTS = ["agent", "verifier", "tenant", "registrar", "ca", "logging"]

# Old configuration files (before versioning was introduced)
OLD_CONFIG_FILES = ["/usr/etc/keylime.conf", "/etc/keylime.conf"]

# Configuration files
CONFIG_FILES = [
    "/usr/etc/keylime/verifier.conf",
    "/etc/keylime/verifier.conf",
    "/usr/etc/keylime/agent.conf",
    "/etc/keylime/agent.conf",
    "/usr/etc/keylime/tenant.conf",
    "/etc/keylime/tenant.conf",
    "/usr/etc/keylime/registrar.conf",
    "/etc/keylime/registrar.conf",
    "/usr/etc/keylime/ca.conf",
    "/etc/keylime/ca.conf",
    "/usr/etc/keylime/logging.conf",
    "/etc/keylime/logging.conf",
]

if "KEYLIME_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_CONFIG"])

if "KEYLIME_AGENT_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_AGENT_CONFIG"])

if "KEYLIME_VERIFIER_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_VERIFIER_CONFIG"])

if "KEYLIME_REGISTRAR_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_REGISTRAR_CONFIG"])

if "KEYLIME_TENANT_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_TENANT_CONFIG"])

if "KEYLIME_CA_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_CA_CONFIG"])

if "KEYLIME_LOGGING_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_LOGGING_CONFIG"])


def get_config(config_files):
    """
    Read configuration files and merge them together
    """

    flat = [s for ss in config_files for s in ss]
    if not flat:
        print(f"No input provided: using {CONFIG_FILES} as input")
        config_files = list(x for x in CONFIG_FILES if os.path.exists(x))
    else:
        config_files = list(x for x in set(flat) if os.path.exists(x))
        if not config_files:
            raise Exception(f"None of the provided files in {set(flat)} exist")

    if not config_files:
        # The configuration files doesn't exist, try old file
        print("Could not find configuration files, trying to find old configuration")
        config_files = list(x for x in OLD_CONFIG_FILES if os.path.exists(x))

    config = configparser.RawConfigParser()
    if not config_files:
        print(f"Could not find configuration files in default locations. Using default values for all options")
    else:
        # Validate that at least one config file was successfully read
        read_files = config.read(config_files)
        if read_files:
            print(f"Successfully read configuration from {read_files}")
        else:
            raise Exception(
                f"Could not parse any configuration from {config_files}, please check the files syntax and permissions"
            )

    return config


def output_component(component, config, template, outfile):
    """
    Output the configuration file for a component
    """

    if os.path.exists(outfile):
        try:
            shutil.copyfile(outfile, outfile + ".bkp")
        except Exception as e:
            print(f"Could not create backup file {outfile + '.bkp'}, aborting...")
            return

    print(f"Writing {component} configuration to {outfile}")

    with open(template, "r", encoding="utf-8") as tf:
        t = tf.read()

        j2 = Template(t)

        r = j2.render(config)

        with open(outfile, "w", encoding="utf-8") as o:
            print(r, file=o)


def output(components, config, templates, outdir):
    """
    Output the requested files using a template
    """

    # Check that there are templates for all components
    for component in components:
        version = config[component]["version"].strip('" ')
        version_dir = os.path.join(templates, version)
        if not os.path.isdir(version_dir):
            raise Exception(f"Could not find directory {version_dir}")

        t = os.path.join(version_dir, f"{component}.j2")
        if not os.path.exists(t):
            raise Exception(f"Template file {t} not found")

        # Set output path
        o = os.path.join(outdir, f"{component}.conf")

        output_component(component, config, t, o)


def needs_update(component, old_config, new_version):
    if component in old_config and "version" in old_config[component]:
        old_version = str_to_version(old_config[component]["version"])
        if old_version >= new_version:
            return False
    return True


def process_mapping(components, old_config, templates, mapping_file, debug=False, target=None):
    """
    Apply the transformations from the provided mapping file to the
    configuration dictionary
    """

    with open(mapping_file, "r", encoding="utf-8") as f:
        try:
            mapping = json.loads(f.read())
        except Exception as e:
            raise Exception(f"Could not load mapping file {mapping_file}: {e}") from e

    if not mapping["version"]:
        raise Exception('Malformed mapping: no "version" set')

    if not mapping["components"]:
        raise Exception('Malformed mapping: no "components" set')

    new_version = str_to_version(mapping["version"])
    if not new_version:
        raise Exception(f"Invalid version number in mapping: {mapping['version']}")

    if not any(map(lambda c: needs_update(c, old_config, new_version), components)):
        print(f"Skipping version {mapping['version']}")
        return old_config

    # Search for the directory containing the templates for the version set in
    # the mapping
    version_dir = os.path.join(templates, mapping["version"])

    if not os.path.isdir(version_dir):
        raise Exception(
            f"Could not find directory {version_dir} for version " f"{mapping['version']} set in {mapping_file}"
        )

    print(f"Applying mapping from file {mapping_file} version {mapping['version']}")

    new = configparser.RawConfigParser()

    for component in mapping["components"].keys():

        if component in old_config:
            if component in mapping["subcomponents"].keys():
                # If the component is a subcomponent, use the version from the
                # component
                version_component = mapping["subcomponents"][component]
            else:
                version_component = component

            # If the configuration file does not contain a version number, assume it is
            # in the old format and use the minimum possible version
            try:
                found_version = old_config.get(version_component, "version")
                old_version = str_to_version(found_version)

                if not old_version:
                    raise Exception("Invalid version number found in old configuration")

            except (configparser.NoOptionError, configparser.NoSectionError):
                print(f"No version found in old configuration for {component}, using '1.0'")
                old_version = (1, 0)
        else:
            # If the old_version does not contain the component from the
            # mapping, use the minimum version to use defaults
            old_version = (1, 0)

        # Skip versions lower than the current version
        if old_version >= new_version:
            new[component] = dict(old_config[component])
            continue

        # Stop if the version reached the target
        if target:
            if old_version >= target:
                new[component] = dict(old_config[component])
                continue

        # Create a new dictionary for each component
        new.add_section(component)
        m = mapping["components"][component]

        for option in m.keys():
            # For each option, get the dictionary with the info to search:
            # {
            #     "section": section to search
            #     "option": option name
            #     "default": value to use in case the option is missing
            info = m[option]
            try:
                new[component][option] = old_config.get(info["section"], info["option"])
            except Exception as e:
                print(f"[{component}] {e} not found: Using default value \"{info['default']}\" for \"{option}\"")
                new[component][option] = info["default"]

        # Set the resulting version for the component
        new[component]["version"] = mapping["version"]

    # If there is an adjust script, load and run it
    adjust_script = os.path.abspath(os.path.join(version_dir, "adjust.py"))
    if os.path.isfile(adjust_script):
        try:
            print(f"Applying adjustment from {adjust_script}")

            # Dynamically load adjust script
            spec = importlib.util.spec_from_file_location("adjust", adjust_script)
            if not spec or not spec.loader:
                raise Exception(f"Could not create spec to load {adjust_script}")

            module = importlib.util.module_from_spec(spec)
            if not module:
                raise Exception(f"Could not load script from {adjust_script}")

            spec.loader.exec_module(module)

            # Run adjust function from adjust script
            execute = getattr(module, "adjust")
            execute(new, mapping)
        except Exception as e:
            print(f"Failed while running adjustment from {adjust_script}: {e}")

    if debug:
        out = {}
        for s in new.sections():
            out[s] = dict(new.items(s))
        print(json.dumps(out, indent=4))

    return new


def str_to_version(v_str):
    """
    Validates the string format and converts the provided string to a tuple of
    ints which can be sorted and compared.

    :returns: Tuple with version number parts converted to int. In case of
    invalid version string, returns None
    """

    # Strip to remove eventual quotes and spaces
    v_str = v_str.strip('" ')

    m = re.match(r"^(\d+)\.(\d+)$", v_str)

    if not m:
        return None

    return tuple(int(x) for x in m.group(1, 2))


def process_versions(components, templates, old_config, target_version=None, debug=False):
    """
    Apply the transformations from the mappings for each version found in the
    templates folder to the configuration.

    If a target version is provided, the process will stop if the target version
    is reached, otherwise all transformations to the latest version are applied
    """

    dirs = os.listdir(templates)

    if not dirs:
        raise Exception(f"No directories found in {templates} for versions")

    # Get a sorted list of the available versions as tuples
    versions = sorted(x for x in set(map(str_to_version, dirs)) if x is not None)

    target = None
    if target_version:
        target = str_to_version(target_version)
        if not target:
            raise Exception(f"Invalid target version number provided: " f"{target_version}")

        if not target in versions:
            raise Exception(f"Directory for target version {target_version} not " f"found in {templates}")

    new = {}

    for version in versions:
        # Find the mapping file for the version and apply
        p = os.path.join(templates, f"{version[0]}.{version[1]}")
        if os.path.isdir(p):
            m = os.path.join(p, "mapping.json")
            if os.path.isfile(m):
                # Apply transformation for the mapping
                new = process_mapping(components, old_config, templates, m, debug=debug, target=target)
                old_config = new
            else:
                raise Exception(f"Could not find mapping {m}")
        else:
            raise Exception(f"Could not find directory {p}")

        if target:
            if version >= target:
                break

    return new


def main():
    parser = argparse.ArgumentParser(description="Split keylime configuration" "file into individual files")

    parser.add_argument(
        "--component",
        help="Select the components for which "
        "configuration files should be generated. If not "
        "provided, generate configuration files for all "
        "components. Can be provided multiple times. "
        "If provided, files will be generated even when up-to-date",
        default=[],
        action="append",
        nargs="+",
    )

    parser.add_argument(
        "--debug",
        help="Print resulting config after each " "applied mapping in JSON format",
        default=False,
        action="store_true",
    )

    parser.add_argument(
        "--input",
        help="Input keylime configuration file to "
        "process. If not provided, it tries to use the "
        "installed Keylime configuration. Can be provided "
        "multiple times",
        default=[],
        action="append",
        nargs="+",
    )

    parser.add_argument(
        "--out",
        help="Output directory where to put the generated files. "
        "If the user is root, the default path is '/etc/keylime', otherwise "
        "the current directory is used. If provided, the files will be "
        "generated even when the configuration is up-to-date. If the output "
        "files exist, backup files are created to preserve the previous "
        "content.",
        default="",
    )

    parser.add_argument(
        "--mapping",
        help="If provided, then only the provided "
        "mapping file will be used. Otherwise, mappings for "
        'each version found in the "templates" directory will '
        "be applied. The file must be a JSON file containing "
        "the mapping for the new configuration options names "
        "to dictionaries containing the section and option "
        "name from the old configuration file, and the default "
        "value to use in case the option is missing in the "
        "input configuration.",
        default=None,
    )

    parser.add_argument(
        "--templates",
        help="Path to the directory containing "
        "the templates for the configuration files. If not "
        'provided "/usr/share/keylime/templates" is used',
        default="/usr/share/keylime/templates",
    )

    parser.add_argument("--version", help="Target version for the output configuration files", default=None)

    parser.add_argument(
        "--defaults",
        help="If provided, the input file and system installed "
        "configuration files will be ignored, and the default "
        "value will be used for all options.",
        default=False,
        action="store_true",
    )

    args = parser.parse_args()

    if not args.out:
        if os.geteuid() == 0:
            out_dir = "/etc/keylime"
        else:
            out_dir = "."
    else:
        out_dir = args.out

    if not os.path.exists(out_dir):
        raise Exception(f"Output directory {out_dir} does not exist")

    if not os.path.isdir(out_dir):
        raise Exception(f"File {out_dir} is not a directory")

    component_list = [s for ss in args.component for s in ss]

    if not component_list:
        # If no component was provided, use all available
        components = COMPONENTS
    else:
        clean = set(component_list)
        for c in clean:
            if not c in COMPONENTS:
                print(f"Unknown component {c}, skipping")
        components = list(clean.intersection(COMPONENTS))

    if args.version and not str_to_version(args.version):
        raise Exception(f"Invalid version {args.version} specified in --version: " f"Expected 'MAJOR.MINOR' format")

    if not os.path.exists(args.templates):
        raise Exception(f"Templates directory {args.templates} does not exist")

    if not os.path.isdir(args.templates):
        raise Exception(f"File {args.templates} is not a directory")

    print(f"Using templates from directory {args.templates}")

    if args.defaults:
        old_config = configparser.RawConfigParser()
    else:
        # Get old configuration
        old_config = get_config(args.input)

    if args.mapping:
        if os.path.isfile(args.mapping):
            mapping_file = args.mapping

            # Apply the single mapping provided
            config = process_mapping(components, old_config, args.templates, mapping_file, debug=args.debug)
        else:
            raise Exception(f"Could not find provided mapping {args.mapping}")
    else:
        # Apply transformations from the templates in the templates directory
        # If a target version is provided, stop when reaching the target
        config = process_versions(components, args.templates, old_config, target_version=args.version, debug=args.debug)

    if config != old_config:
        output(components, config, args.templates, out_dir)
    else:
        print("Configuration is up-to-date")
        if args.out or component_list:
            # If the output directory or component list were specified, write the files even when
            # up-to-date
            output(components, config, args.templates, out_dir)


if __name__ == "__main__":
    main()

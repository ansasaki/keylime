import configparser
import importlib
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from io import StringIO

from keylime.cmd import convert_config

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CONFIG_DIR = os.path.abspath(os.path.join(DATA_DIR, "config"))
TEMPLATES_DIR = os.path.abspath(os.path.join(DATA_DIR, "templates"))
MAPPINGS_DIR = os.path.abspath(os.path.join(DATA_DIR, "mappings"))
COMPONENTS = ["comp1", "comp2"]


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestConvertConfig(unittest.TestCase):
    def setUp(self):
        # Set configuration files used for testing
        convert_config.CONFIG_FILES = list(os.path.join(CONFIG_DIR, f"{comp}.conf") for comp in COMPONENTS)
        convert_config.OLD_CONFIG_FILES = list(os.path.join(CONFIG_DIR, f"{comp}_old.conf") for comp in COMPONENTS)

    def tearDown(self):
        importlib.reload(convert_config)

    def testGetConfig(self):
        """Sanity test for get_config()"""

        existing_path = os.path.join(CONFIG_DIR, "comp1_exist.conf")
        self.assertTrue(os.path.exists(existing_path))

        # Provide existing file as input
        config = convert_config.get_config([[existing_path]])

        value = config.get("comp1", "test_option", fallback="Not found")
        # Check that the file was correctly parsed
        self.assertEqual(value, "existing")

    def testGetConfigNoInput(self):
        """Test get_config() without providing input"""

        # Provide no input
        config = convert_config.get_config([[]])

        # Check that CONFIG_FILES were correctly parsed
        value = config.get("comp1", "test_option", fallback="Not found")

        self.assertEqual(value, "current")

    def testGetConfigNoneExisting(self):
        """Test get_config() where none of the files exist"""

        # Provide non-existing files as input and expect exception
        self.assertRaises(Exception, convert_config.get_config, "non-existing.conf")

    def testGetConfigOld(self):
        """Test get_config() when it should fall back to old file"""

        # Set CONFIG_FILES to non existing files
        convert_config.CONFIG_FILES = ["non-existing.conf"]

        # Give no input
        config = convert_config.get_config([[]])

        # Check that OLD_CONFIG_FILES were correctly parsed
        value = config.get("comp1", "test_option", fallback="Not found")

        self.assertEqual(value, "old")

    def testGetConfigDefault(self):
        """Test get_config() when it should use default values"""

        # Set CONFIG_FILES to non existing files
        convert_config.CONFIG_FILES = ["non-existing.conf"]

        # Set OLD_CONFIG_FILES to non existing files
        convert_config.OLD_CONFIG_FILES = ["non-existing.conf"]

        # Give no input
        config = convert_config.get_config([[]])

        # Check that an empty RawConfigParser was returned
        self.assertTrue(isinstance(config, configparser.RawConfigParser))
        self.assertEqual(len(config.keys()), 1)
        self.assertEqual(list(config.keys()), ["DEFAULT"])
        self.assertEqual(len(list(config.items("DEFAULT"))), 0)

    def testOutputComponent(self):
        """Test that given a config and template, the output is generated"""

        template_path = os.path.join(TEMPLATES_DIR, "2.0/comp1.j2")
        self.assertTrue(os.path.exists(template_path))

        # Create a configuration
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "2.0"
        config["comp1"]["test_option"] = "generated"
        config["comp1"]["test_adjust"] = "generated"
        config.add_section("subcomp1")
        config["subcomp1"]["suboption"] = "generated"

        # Provide configuration and template
        with tempfile.TemporaryDirectory() as tempdir:
            outfile = os.path.join(tempdir, "output.conf")
            convert_config.output_component("comp1", config, template_path, outfile)

            # Check that the file was correctly generated
            self.assertTrue(os.path.exists(outfile))

            generated = configparser.ConfigParser()
            l = generated.read(outfile)
            self.assertTrue(outfile in l)
            self.assertEqual(generated.get("comp1", "test_option"), "generated")
            self.assertEqual(generated.get("comp1", "test_adjust"), "generated")
            self.assertEqual(generated.get("subcomp1", "suboption"), "generated")

    def testOutputNoVersion(self):
        """Test that if the version doesn't exist, the output fails"""

        # Provide config where the template for a given component version
        # doesn't exist and check that it raises Exception

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "5.0"

        with tempfile.TemporaryDirectory() as tempdir:
            self.assertRaises(Exception, convert_config.output, ["comp1"], config, TEMPLATES_DIR, tempdir)

    def testOutputNoTemplate(self):
        """Test that if the template is not available, the output fails"""

        # Provide config where the version directory exists, but the template
        # for the given component doesn't and check that it raises Exception

        config = configparser.RawConfigParser()
        config.add_section("comp3")
        config["comp3"]["version"] = "2.0"

        with tempfile.TemporaryDirectory() as tempdir:
            self.assertRaises(Exception, convert_config.output, ["comp3"], config, TEMPLATES_DIR, tempdir)

    def testOutput(self):
        """Sanity test for output()"""

        # Create a configuration
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "2.0"
        config["comp1"]["test_option"] = "generated"
        config["comp1"]["test_adjust"] = "generated"
        config.add_section("subcomp1")
        config["subcomp1"]["suboption"] = "generated"

        with tempfile.TemporaryDirectory() as tempdir:
            convert_config.output(["comp1"], config, TEMPLATES_DIR, tempdir)

            outfile = os.path.join(tempdir, "comp1.conf")
            self.assertTrue(os.path.exists(outfile))

            generated = configparser.ConfigParser()
            l = generated.read(outfile)
            self.assertTrue(outfile in l)
            self.assertEqual(generated.get("comp1", "test_option"), "generated")
            self.assertEqual(generated.get("comp1", "test_adjust"), "generated")
            self.assertEqual(generated.get("subcomp1", "suboption"), "generated")

    def testNeedsUpdate(self):
        """Test needs_update()"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")

        # Assert that without version, it will always need update
        self.assertTrue(convert_config.needs_update("comp1", config, (0, 0)))

        config["comp1"]["version"] = "2.0"
        self.assertTrue(convert_config.needs_update("comp1", config, (3, 0)))
        self.assertFalse(convert_config.needs_update("comp1", config, (2, 0)))

    def testProcessMapping(self):
        """Sanity test for process_mapping()"""

        # Use default configuration files
        config = convert_config.get_config([[]])

        # Use sanity mapping (default)
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        with captured_output() as (out, err):
            result = convert_config.process_mapping(COMPONENTS, config, TEMPLATES_DIR, mapping)

        self.assertTrue(isinstance(result, configparser.RawConfigParser))

        # Check that option not found uses default value
        self.assertTrue("test_default" in result["comp1"])
        self.assertEqual(result.get("comp1", "test_default"), "default")

        # Check that added option is present
        self.assertTrue("test_added" in result["comp1"])

        # Check removed option is not present
        self.assertFalse("test_option" in result["comp2"])

        # Check that adjust is correctly applied
        self.assertEqual(result.get("comp1", "test_adjust"), "adjusted 3.0")

        # Check that when the component does not have a version, the smallest
        # number is used
        self.assertTrue("No version found in old configuration for comp1, using '1.0'" in out.getvalue())

    def testProcessNonExistingMapping(self):
        """Check that non-existing mapping raises Exception"""
        config = configparser.RawConfigParser()
        self.assertRaises(
            Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, "non-existing-mapping"
        )

    def testProcessMappingNoVersion(self):
        """Check that mapping without version raises Exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "no-version.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def testProcessMappingNoComponents(self):
        """Check that mapping without components raises exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "no-components.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def testProcessMappingInvalidVersion(self):
        """Check that invalid version number (not parseable) raises exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "invalid-version.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def testProcessMappingAlreadyUpdated(self):
        """Check that if all components are updated, the process is short
        circuited and returns earlier"""
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "3.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "3.0"
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        with captured_output() as (out, err):
            result = convert_config.process_mapping(COMPONENTS, config, TEMPLATES_DIR, mapping)
            self.assertEqual(result, config)
        # Check that the output shows that the updated version was skipped
        self.assertTrue("Skipping version 3.0" in out.getvalue())

    def testProcessMappingMissingVersion(self):
        """Check that missing version in templates directory raises exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        # Use empty directory as the templates directory and check that raises
        # Exception
        with tempfile.TemporaryDirectory() as tempdir:
            self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, tempdir, mapping)

    def testProcessMappingInvalidComponentVersion(self):
        """Check that if a component in the config does not have a parseable
        version, it raises exception
        """
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "notversion"

        # Use string not parseable as version and check that raises Exception
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def testProcessMappingMissingAdjustMethod(self):
        """Check that adjust script without adjust() method it raises
        exception
        """

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"

        template = os.path.join(DATA_DIR, "template-no-adjust")
        self.assertTrue(os.path.exists(template))

        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, template, mapping)

    def testProcessMappingInvalidAdjustFile(self):
        """Check that invalid file as adjust script raises exception (not python
        loadable)
        """

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"

        template = os.path.join(DATA_DIR, "template-invalid-adjust")
        self.assertTrue(os.path.exists(template))

        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, template, mapping)

    def testProcessMappingAdjustException(self):
        """Check that if adjust raises exception, the exception is re-raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"

        template = os.path.join(DATA_DIR, "template-adjust-exception")
        self.assertTrue(os.path.exists(template))

        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, template, mapping)

    def testProcessVersions(self):
        """Sanity test for the config upgrade process through all versions"""

        config = convert_config.get_config([[]])

        with captured_output() as (out, err):
            result = convert_config.process_versions(COMPONENTS, TEMPLATES_DIR, config)

        value = result.get("comp1", "test_option")
        # Check that the file was correctly parsed
        self.assertEqual(value, "current")
        value = result.get("comp1", "test_adjust")
        self.assertEqual(value, "adjusted 3.0")
        value = result.get("comp1", "version")
        self.assertEqual(value, "3.0")

        # Check that versions lower than the current version are skipped for
        # each component.
        self.assertEqual(result.get("comp1", "oldest_used"), "2.0")
        self.assertEqual(result.get("comp2", "oldest_used"), "3.0")

        # Check that subcomponent correctly inherits version from parent
        self.assertEqual(result.get("subcomp1", "version"), "3.0")

    def testProcessVersionsTargetVersion(self):
        """Check that the update stops at the target version, when it is set"""

        config = convert_config.get_config([[]])
        result = convert_config.process_versions(COMPONENTS, TEMPLATES_DIR, config, target_version="2.0")
        self.assertEqual(result.get("comp1", "version"), "2.0")
        self.assertEqual(result.get("comp2", "version"), "2.0")

    def testStrToVersion(self):
        """Sanity test for the conversion of a version string to a tuple"""

        self.assertEqual(convert_config.str_to_version("12.34"), (12, 34))
        self.assertEqual(convert_config.str_to_version("not version"), None)
        self.assertEqual(convert_config.str_to_version(' "12.34" '), (12, 34))
        self.assertEqual(convert_config.str_to_version('"   12.34"   '), (12, 34))

    def testProcessVersionsUsingTOML(self):
        """Test that using TOML files as old configs does not break"""
        toml = os.path.join(CONFIG_DIR, "comp1.toml")
        self.assertTrue(os.path.exists(toml))

        config = convert_config.get_config([[toml]])

        result = convert_config.process_versions(["comp1"], TEMPLATES_DIR, config)
        self.assertEqual(result.get("comp1", "version"), "3.0")
        self.assertEqual(result.get("comp1", "test_option"), "current")

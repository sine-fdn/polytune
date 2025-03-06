#! /usr/bin/env python3

import os
import argparse
import subprocess
import sys


def shell(command, expect=0, cwd=None, env={}):
    subprocess_stdout = subprocess.DEVNULL

    print("Env:", env)
    print("Command: ", end="")
    for i, word in enumerate(command):
        if i == 4:
            print("'{}' ".format(word), end="")
        else:
            print("{} ".format(word), end="")

    print("\nDirectory: {}".format(cwd))

    os_env = os.environ
    os_env.update(env)

    ret = subprocess.run(command, cwd=cwd, env=os_env)
    if ret.returncode != expect:
        raise Exception("Error {}. Expected {}.".format(ret, expect))


parser = argparse.ArgumentParser(description="Extract and run proofs using hax.")

sub_parser = parser.add_subparsers(
    description="Extract or typecheck F*",
    dest="sub",
    help="Extract or typecheck F*.",
)
extract_parser = sub_parser.add_parser("extract-fstar")
typecheck_parser = sub_parser.add_parser("typecheck-fstar")

typecheck_parser.add_argument(
    "--lax",
    action="store_true",
    dest="lax",
    help="Lax typecheck the code only",
)
typecheck_parser.add_argument(
    "--admit",
    action="store_true",
    dest="admit",
    help="Set admit_smt_queries to true for typechecking",
)
typecheck_parser.add_argument(
    "--clean",
    action="store_true",
    dest="clean",
    help="Clean before calling make",
)

options = parser.parse_args()

cargo_hax_into = [
    "cargo",
    "hax",
    "-C", # Arguments to pass to `cargo build`, terminated by a semi-colon
    "-p",
    "polytune",
    "--features",
    "is_sync",
    ";",
    "into",
]

# These will be extracted to F* by hax.
extraction_targets = [
    "-i",
    "-** +**::faand::combine_two_leaky_ands"
]

# For these, hax will generate only interfaces in F*.
interface_extraction_targets = [
    "--interfaces",
]

hax_env = {}

if options.sub == "extract-fstar":
    # The extract sub command.
    shell(
        cargo_hax_into + extraction_targets + ["fstar"]
        #+ interface_extraction_targets
        ,
        cwd=".",
        env=hax_env,
    )
elif options.sub == "typecheck-fstar":
    # Typecheck subcommand.
    custom_env = {}
    if options.lax:
        custom_env.update({"OTHERFLAGS": "--lax"})
    if options.admit:
        custom_env.update({"OTHERFLAGS": "--admit_smt_queries true"})
    if options.clean:
        shell(["make", "-C", "proofs/fstar/extraction/", "clean"])
    shell(["make", "-C", "proofs/fstar/extraction/"], env=custom_env)
    exit(0)
else:
    parser.print_help()
    exit(2)

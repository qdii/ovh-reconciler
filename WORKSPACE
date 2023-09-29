workspace(name = "ovh_reconciler")

# Load the bazel rules related to python from the latest archive.
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
# The WORKSPACE should define the interpreter used in the Bazel sandbox.
# At the time of writing the most recent version is python 3.11.
http_archive(
    name = "rules_python",
    sha256 = "5868e73107a8e85d8f323806e60cad7283f34b32163ea6ff1020cf27abef6036",
    strip_prefix = "rules_python-0.25.0",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.25.0.tar.gz",
)
load("@rules_python//python:repositories.bzl", "py_repositories")
py_repositories()

# To ensure reproducibility we also want to fix the version of the
# modules, and use pip to install them.
load("@rules_python//python:pip.bzl", "pip_parse")
pip_parse(
    name = "pip_deps",
    requirements_lock = ":requirements.txt",
)
load("@pip_deps//:requirements.bzl", "install_deps")
install_deps()


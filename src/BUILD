load("@pip_deps//:requirements.bzl", "requirement")

py_binary(
  name="ovh_reconciler",
  srcs=["ovh_reconciler.py"],
  deps=[
    requirement("absl-py"),
    requirement("certifi"),
    requirement("charset-normalizer"),
    requirement("idna"),
    requirement("ovh"),
    requirement("parameterized"),
    requirement("requests"),
    requirement("urllib3"),
  ],
)

py_test(
  name="ovh_reconciler_test",
  srcs=["ovh_reconciler_test.py"],
  deps=[
    ":ovh_reconciler",
  ],
)

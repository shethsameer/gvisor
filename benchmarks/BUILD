load("//tools:defs.bzl", "pkg_tar")

package(licenses = ["notice"])

pkg_tar(
    name = "installers",
    srcs = [
        "//tools/installers:head",
        "//tools/installers:master",
        "//tools/installers:runsc",
    ],
    mode = "0755",
)

filegroup(
    name = "files",
    srcs = [
        ":installers",
    ],
)

py_binary(
    name = "benchmarks",
    srcs = ["run.py"],
    data = [
        ":files",
        "//tools/images:ubuntu1604",
        "//tools/images:zone",
    ],
    main = "run.py",
    python_version = "PY3",
    srcs_version = "PY3",
    tags = [
        "local",
        "manual",
    ],
    deps = ["//benchmarks/runner"],
)

workspace(name = "tink_go_gcpkms")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Release X.25.2 from 2024-01-09.
http_archive(
    name = "com_google_protobuf",
    sha256 = "5e8e2b369a6fcaa24fada21135782eef147aec467cd286c108936a3277e88d2b",
    strip_prefix = "protobuf-25.2",
    urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v25.2/protobuf-25.2.zip"],
)

# Release from 2023-04-20
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "6dc2da7ab4cf5d7bfc7c949776b1b7c733f05e56edc4bcd9022bb249d2e2a996",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.39.1/rules_go-v0.39.1.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.39.1/rules_go-v0.39.1.zip",
    ],
)

# Release from 2023-01-14
http_archive(
    name = "bazel_gazelle",
    sha256 = "ecba0f04f96b4960a5b250c8e8eeec42281035970aa8852dda73098274d14a1d",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.29.0/bazel-gazelle-v0.29.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.29.0/bazel-gazelle-v0.29.0.tar.gz",
    ],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

# Tink Go Google Cloud KMS Deps.
load("//:deps.bzl", "tink_go_gcpkms_dependencies")

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

protobuf_deps()

# gazelle:repository_macro deps.bzl%tink_go_gcpkms_dependencies
tink_go_gcpkms_dependencies()

go_rules_dependencies()

go_register_toolchains(
    nogo = "@//:tink_nogo",
    version = "1.20.10",
)

gazelle_dependencies()

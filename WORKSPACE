workspace(name = "tink_go_gcpkms")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_file(
    name = "google_root_pem",
    executable = 0,
    sha256 = "9c9b9685ad319b9747c3fe69b46a61c11a0efabdfa09ca6a8b0c3da421036d27",
    urls = ["https://pki.goog/roots.pem"],
)

# -------------------------------------------------------------------------
# Bazel Skylib.
# -------------------------------------------------------------------------
# Release from 2023-02-09
# Protobuf vX.21.9 imports a version of bazel-skylib [1] that is incompatible
# with the one required by bazel-gazelle, so we make sure we have a newer
# version [2].
#
# [1] https://github.com/protocolbuffers/protobuf/blob/90b73ac3f0b10320315c2ca0d03a5a9b095d2f66/protobuf_deps.bzl#L28
# [2] https://github.com/bazelbuild/bazel-gazelle/issues/1290#issuecomment-1312809060
http_archive(
    name = "bazel_skylib",
    sha256 = "b8a1527901774180afc798aeb28c4634bdccf19c4d98e7bdd1ce79d1fe9aaad7",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.1/bazel-skylib-1.4.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.1/bazel-skylib-1.4.1.tar.gz",
    ],
)

# -------------------------------------------------------------------------
# Protobuf.
# -------------------------------------------------------------------------
# proto_library, cc_proto_library and java_proto_library rules implicitly
# depend respectively on:
#   * @com_google_protobuf//:proto
#   * @com_google_protobuf//:cc_toolchain
#   * @com_google_protobuf//:java_toolchain
# This statement defines the @com_google_protobuf repo.
# Release X.21.9 from 2022-10-26.
http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-21.9",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/refs/tags/v21.9.zip"],
    sha256 = "5babb8571f1cceafe0c18e13ddb3be556e87e12ceea3463d6b0d0064e6cc1ac3",
)

# -------------------------------------------------------------------------
# Wycheproof.
# -------------------------------------------------------------------------
# Commit from 2019-12-17
http_archive(
    name = "wycheproof",
    sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
    strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
    url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
)

# -------------------------------------------------------------------------
# Bazel rules for Go.
# -------------------------------------------------------------------------
# Release from 2023-04-20
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "6dc2da7ab4cf5d7bfc7c949776b1b7c733f05e56edc4bcd9022bb249d2e2a996",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.39.1/rules_go-v0.39.1.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.39.1/rules_go-v0.39.1.zip",
    ],
)

# -------------------------------------------------------------------------
# Bazel Gazelle.
# -------------------------------------------------------------------------
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
    version = "1.19.9",
)

gazelle_dependencies()

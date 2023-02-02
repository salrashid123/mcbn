package(default_visibility=["//visibility:public"])

load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@build_bazel_rules_nodejs//:index.bzl", "nodejs_binary")
load("@io_bazel_rules_docker//nodejs:image.bzl", "nodejs_image")

nodejs_binary(
    name = "main",
    entry_point = ":main.js",
    data = [":main.js", "@npm//express"],
    toolchain = "@nodejs_linux_amd64//:node_toolchain",
)

nodejs_image(
    name = "node_image",
    binary = ":main",
    node_repository_name = "nodejs_linux_amd64",
    include_node_repo_args = False,
    visibility = ["//visibility:private"],
    base = "@google-appengine-debian9//image",
)

container_image(
    name = "server_image",
    base = ":node_image",
    cmd = ["/app/main"], 
    directory = "/app",
    ports = ["8081"],
    repository = "us-central1-docker.pkg.dev/builder-project/repo1/node_server",
)



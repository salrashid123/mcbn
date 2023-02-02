"""
External repositories used in this workspace.
"""

load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_repositories():
    go_repository(
        name = "com_github_davecgh_go_spew",
        importpath = "github.com/davecgh/go-spew",
        sum = "h1:ZDRjVQ15GmhC3fiQ8ni8+OwkZQO4DARzQgrnXU1Liz8=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_pion_dtls_v2",
        importpath = "github.com/pion/dtls/v2",
        sum = "h1:jlh2vtIyUBShchoTDqpCCqiYCyRFJ/lvf/gQ8TALs+c=",
        version = "v2.1.5",
    )
    go_repository(
        name = "com_github_pion_logging",
        importpath = "github.com/pion/logging",
        sum = "h1:M9+AIj/+pxNsDfAT64+MAVgJO0rsyLnoJKCqf//DoeY=",
        version = "v0.2.2",
    )
    go_repository(
        name = "com_github_pion_transport",
        importpath = "github.com/pion/transport",
        sum = "h1:KWTA5ZrQogizzYwPEciGtHPLwpAjE91FgXnyu+Hv2uY=",
        version = "v0.13.0",
    )
    go_repository(
        name = "com_github_pion_udp",
        importpath = "github.com/pion/udp",
        sum = "h1:8UAPvyqmsxK8oOjloDk4wUt63TzFe9WEJkg5lChlj7o=",
        version = "v0.1.1",
    )

    go_repository(
        name = "com_github_pmezard_go_difflib",
        importpath = "github.com/pmezard/go-difflib",
        sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_stretchr_objx",
        importpath = "github.com/stretchr/objx",
        sum = "h1:4G4v2dO3VZwixGIRoQ5Lfboy6nUhCyYzaqnIAPPhYs4=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_stretchr_testify",
        importpath = "github.com/stretchr/testify",
        sum = "h1:nwc3DEeHmmLAfoZucVR881uASk0Mfjw8xYJ99tb5CcY=",
        version = "v1.7.0",
    )

    go_repository(
        name = "in_gopkg_check_v1",
        importpath = "gopkg.in/check.v1",
        sum = "h1:yhCVgyC4o1eVCa2tZl7eS0r+SDo693bJlVdllGtEeKM=",
        version = "v0.0.0-20161208181325-20d25e280405",
    )

    go_repository(
        name = "in_gopkg_yaml_v3",
        importpath = "gopkg.in/yaml.v3",
        sum = "h1:dUUwHk2QECo/6vqA44rthZ8ie2QXMNeKRTHCNY2nXvo=",
        version = "v3.0.0-20200313102051-9f266ea9e77c",
    )

    go_repository(
        name = "org_golang_x_crypto",
        importpath = "golang.org/x/crypto",
        sum = "h1:OeJjE6G4dgCY4PIXvIRQbE8+RX+uXZyGhUy/ksMGJoc=",
        version = "v0.0.0-20220427172511-eb4f295cb31f",
    )

    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        sum = "h1:HVyaeDAYux4pnY+D/SiwmLOR36ewZ4iGQIIrtnuCjFA=",
        version = "v0.0.0-20220425223048-2871e0cb64e4",
    )

    go_repository(
        name = "org_golang_x_sys",
        importpath = "golang.org/x/sys",
        sum = "h1:fLOSk5Q00efkSvAm+4xcoXD+RRmLmmulPn5I3Y9F2EM=",
        version = "v0.0.0-20211216021012-1d35b9e2eb4e",
    )
    go_repository(
        name = "org_golang_x_term",
        importpath = "golang.org/x/term",
        sum = "h1:JGgROgKl9N8DuW20oFS5gxc+lE67/N3FcwmBPMe7ArY=",
        version = "v0.0.0-20210927222741-03fcf44c2211",
    )
    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        sum = "h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=",
        version = "v0.3.7",
    )
    go_repository(
        name = "org_golang_x_tools",
        importpath = "golang.org/x/tools",
        sum = "h1:FDhOuMEY4JVRztM/gsbk+IKUQ8kj74bxZrgw87eMMVc=",
        version = "v0.0.0-20180917221912-90fa682c2a6e",
    )

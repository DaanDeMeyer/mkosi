# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import Distribution, fedora
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die
from mkosi.util import listify


class Installer(fedora.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Amazon Linux"

    @classmethod
    def default_release(cls) -> str:
        return "2023"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.fedora

    @classmethod
    def setup(cls, context: Context, *, dbpath: str = "/var/lib/rpm") -> None:
        super().setup(context, dbpath=dbpath)

    @classmethod
    @listify
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        gpgurls = (
            find_rpm_gpgkey(
                context,
                key=f"RPM-GPG-KEY-amazon-linux-{context.config.release}",
            ) or f"https://github.com/xsuchy/distribution-gpg-keys/blob/main/keys/amazon-linux/RPM-GPG-KEY-amazon-linux-{context.config.release}",
        )

        if context.config.local_mirror:
            yield RpmRepository("amazonlinux", f"baseurl={context.config.local_mirror}", gpgurls)
            return

        mirror = context.config.mirror or "https://cdn.amazonlinux.com"

        yield RpmRepository(
            "amazonlinux",
            f"mirrorlist={mirror}/al{context.config.release}/core/mirrors/latest/$basearch/mirror.list",
            gpgurls,
        )
        yield RpmRepository(
            "amazonlinux-debuginfo",
            f"mirrorlist={mirror}/al{context.config.release}/core/mirrors/latest/debuginfo/$basearch/mirror.list",
            gpgurls,
            enabled=False,
        )
        yield RpmRepository(
            "amazonlinux-source",
            f"mirrorlist={mirror}/al{context.config.release}/core/mirrors/latest/SRPMS/mirror.list",
            gpgurls,
            enabled=False,
        )

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a

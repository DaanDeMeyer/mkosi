# SPDX-License-Identifier: LGPL-2.1+

import os
import subprocess
import secrets
import textwrap
import tempfile
import sys
from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
)
from mkosi.log import ARG_DEBUG, die
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd, finalize_crypto_mounts
from mkosi.util import INVOKING_USER, sort_packages, umask


def setup_keyring(context: Context) -> None:
    gpgdir = context.pkgmngr / "etc/portage/gnupg"

    with umask(~0o700):
        gpgdir.mkdir(exist_ok=True, parents=True)

    pw = secrets.token_hex(32)

    env = dict(GNUPGHOME=os.fspath(gpgdir))
    if sys.stderr.isatty():
        env |= dict(GPG_TTY=os.ttyname(sys.stderr.fileno()))

    with tempfile.NamedTemporaryFile(mode="w") as f:
        f.write(
            textwrap.dedent(
                f"""\
                %echo Generating Portage local OpenPGP trust key
                Key-Type: RSA
                Key-Length: 3072
                Subkey-Type: RSA
                Subkey-Length: 3072
                Name-Real: Portage Local Trust Key
                Name-Comment: local signing only
                Name-Email: portage@localhost
                Expire-Date: 0
                Passphrase: {pw}
                %commit
                %echo done
                """
            )
        )
        f.flush()

        run(["gpg", "--batch", "--generate-key", f.name], env=env)

    with umask(~0o600):
        passphrase = (context.pkgmngr / "etc/portage/gnupg/pass")
        passphrase.write_text(pw)

    primary = run(
        [
            "gpg",
            "--batch",
            "--list-secret-keys",
            "--keyid-format=long",
            "--with-colons",
        ],
        stdout=subprocess.PIPE,
        env=env,
    ).stdout.strip().splitlines()[0].removeprefix("fpr").strip(":")

    keyring = run(["curl", "https://qa-reports.gentoo.org/output/service-keys.gpg"], stdout=subprocess.PIPE, text=False).stdout
    run(["gpg", "--batch", "--import"], input=keyring, text=False, env=env)

    keys = run(
        [
            "gpg",
            "--batch",
            "--list-keys",
            "--keyid-format=long",
            "--with-colons",
        ],
        stdout=subprocess.PIPE,
        env=env,
    ).stdout.strip().splitlines()

    keys = [key.removeprefix("fpr").strip(":") for key in keys if key.startswith("fpr")]
    keys = [key for key in keys if key != primary]

    for key in keys:
        run(
            [
                "gpg",
                "--command-fd=0",
                "--yes",
                "--no-tty",
                "--passphrase-file", passphrase,
                "--pinentry-mode=loopback",
                "--lsign-key", key,
            ],
            env=env,
            input="y\ny\n",
        )

    run(["gpg", "--batch", "--check-trustdb"], env=env)


def setup_emerge(context: Context) -> None:
    setup_keyring(context)
    # Set up a basic profile to trick emerge into proceeding (we don't care about the profile since we're
    # only installing binary packages). See https://bugs.gentoo.org/470006.
    make_profile = context.pkgmngr / "etc/portage/make.profile"
    make_profile.mkdir(parents=True, exist_ok=True)
    (make_profile / "make.defaults").write_text(
        textwrap.dedent(
            f"""\
            ARCH="{context.config.distribution.architecture(context.config.architecture)}"
            ACCEPT_KEYWORDS="**"
            PORTAGE_USERNAME="root"
            PORTAGE_GRPNAME="root"
            PORTAGE_TMPDIR="/var/tmp"
            PORTDIR="{context.cache_dir}"
            PKGDIR="{context.cache_dir / "cache/binpkgs"}"
            GPG_VERIFY_USER_DROP=""
            GPG_VERIFY_GROUP_DROP=""
            BINPKG_FORMAT="gpkg"
            """
        )
    )
    (make_profile / "parent").write_text("/var/empty")
    (make_profile / "use.force").write_text("-split-usr")

    features = " ".join([
        # Disable sandboxing in emerge because we already do it in mkosi.
        "-sandbox",
        "-pid-sandbox",
        "-ipc-sandbox",
        "-network-sandbox",
        "-userfetch",
        "-userpriv",
        "-usersandbox",
        "-usersync",
        "-ebuild-locks",
        "parallel-fetch",
        "parallel-install",
        *(["noman", "nodoc", "noinfo"] if context.config.with_docs else []),
    ])

    # Setting FEATURES via the environment variable does not seem to apply to ebuilds in portage, so we
    # append to /etc/portage/make.conf instead.
    with (context.pkgmngr / "etc/portage/make.conf").open("a") as f:
        f.write(f"\nFEATURES=\"${{FEATURES}} {features}\"\n")

    mirror = context.config.mirror or "https://distfiles.gentoo.org"

    (context.pkgmngr / "etc/portage/binrepos.conf").write_text(
        textwrap.dedent(
            f"""\
            [binhost]
            sync-uri = {mirror}/releases/amd64/binpackages/17.1/x86-64/
            priority = 10
            """
        )
    )


def invoke_emerge(context: Context, packages: Sequence[str] = (), apivfs: bool = True) -> None:
    run(
        [
            "emerge",
            "--tree",
            "--usepkgonly=y",
            "--getbinpkg=y",
            "--jobs",
            "--load-average",
            "--root-deps=rdeps",
            "--with-bdeps=n",
            "--verbose-conflicts",
            "--noreplace",
            *(["--verbose"] if ARG_DEBUG.get() else ["--quiet-build", "--quiet"]),
            *sort_packages(packages),
        ],
        env=dict(
            PORTAGE_REPOSITORIES="",
            ROOT=os.fspath(context.root),
            BROOT=os.fspath(context.root),
            SYSROOT=os.fspath(context.root),
            USE="-split-usr",
        ) | context.config.environment,
        sandbox=(
            context.sandbox(
                network=True,
                options=[
                    "--dir", "/var/empty",
                    "--bind", context.root, context.root,
                    "--bind", context.cache_dir, context.cache_dir,
                    "--bind", INVOKING_USER.home() / ".local", INVOKING_USER.home() / ".local",
                    *finalize_crypto_mounts(tools=context.config.tools()),
                ],
            ) + [
                "sh",
                "-c",
                f"mount -t overlay -o lowerdir={INVOKING_USER.home() / '.local'}:/usr overlayfs /usr && exec $0 \"$@\"",
            ] + (apivfs_cmd(context.root, tools=context.config.tools()) if apivfs else [])
        ),
    )


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Gentoo"

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.ebuild

    @classmethod
    def default_release(cls) -> str:
        return "17.1"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.gentoo

    @classmethod
    def setup(cls, context: Context) -> None:
        setup_emerge(context)

    @classmethod
    def install(cls, context: Context) -> None:
        # First, we set up merged usr.
        # This list is taken from https://salsa.debian.org/installer-team/debootstrap/-/blob/master/functions#L1369.

        with umask(~0o755):
            for d in ("bin", "sbin", "lib", "lib64"):
                (context.root / d).symlink_to(f"usr/{d}")
                (context.root / f"usr/{d}").mkdir(parents=True, exist_ok=True)

        cls.install_packages(context, packages=["sys-apps/baselayout"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_emerge(context, packages=packages, apivfs=apivfs)

        for d in context.root.glob("usr/src/linux-*"):
            kver = d.name.removeprefix("linux-")
            kimg = d / {
                Architecture.x86_64: "arch/x86/boot/bzImage",
                Architecture.arm64: "arch/arm64/boot/Image.gz",
                Architecture.arm: "arch/arm/boot/zImage",
            }[context.config.architecture]
            vmlinuz = context.root / "usr/lib/modules" / kver / "vmlinuz"
            if not vmlinuz.exists() and not vmlinuz.is_symlink():
                vmlinuz.symlink_to(os.path.relpath(kimg, start=vmlinuz.parent))

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "amd64",
            Architecture.arm64  : "arm64",
            Architecture.arm    : "arm",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Gentoo")

        return a

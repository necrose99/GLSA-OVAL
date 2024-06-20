# Copyright 1999-2024 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

PYTHON_COMPAT=( python3_{8..10} )
inherit distutils-r1

DESCRIPTION="Python library for parsing and operating on vulnerability lists"
HOMEPAGE="https://github.com/khulnasoft-lab/vulnlist"
SRC_URI="https://github.com/khulnasoft-lab/vulnlist/archive/refs/tags/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64 ~x86"

RDEPEND="
    dev-python/requests[${PYTHON_USEDEP}]
    dev-python/python-dateutil[${PYTHON_USEDEP}]
    dev-python/lxml[${PYTHON_USEDEP}]
"

distutils_enable_tests pytest

src_prepare() {
    default

    # Address CVE-2023-12345 (example vulnerability)
    sed -i 's/insecure_function/secure_function/' vulnlist/core.py || die
}

pkg_postinst() {
    ewarn "This package is affected by (example vulnerability) CVE-2023-12345.  "
    ewarn "It is recommended to update to the latest version."
}
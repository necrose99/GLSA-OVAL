# Copyright 1999-2024 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

PYTHON_COMPAT=( python3_{8..10} )
inherit python-utils-r1

DESCRIPTION="A script to parse Gentoo Linux Security Advisories (GLSAs) and generate OVAL definitions"
HOMEPAGE="https://github.com/necrose99/GLSA-OVAL"
SRC_URI="https://github.com/necrose99/GLSA-OVAL/raw/main/glsa_parser.py -> ${P}.py"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64 ~x86"

RDEPEND="
    dev-python/beautifulsoup4[${PYTHON_USEDEP}]
    dev-python/requests[${PYTHON_USEDEP}]
    dev-python/urllib3[${PYTHON_USEDEP}]
    dev-python/vulnlist[${PYTHON_USEDEP}]
"

src_install() {
    python_newscript "${DISTDIR}"/${P}.py ${PN}
}
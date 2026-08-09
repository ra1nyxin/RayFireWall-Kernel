#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

if [ "$#" -ne 4 ]; then
    echo "用法: $0 <deb|rpm|arch> <平台名> <内核版本> <输出目录>" >&2
    exit 64
fi

FORMAT=$1
PLATFORM=$2
KERNEL_RELEASE=$3
OUTPUT_DIR=$4
VERSION=0.1.0
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rayfw-package.XXXXXX")
# Arch's makepkg runs as an unprivileged builder; allow it to traverse the
# temporary parent. The directory is removed by the trap after packaging.
chmod 0755 "$WORK_DIR"

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

stage_payload() {
    target=$1

    install -Dm0755 "$PROJECT_DIR/cli/rayfwctl" "$target/usr/sbin/rayfwctl"
    install -Dm0644 "$PROJECT_DIR/kernel/rayfw.ko" \
        "$target/lib/modules/$KERNEL_RELEASE/extra/rayfw.ko"
    install -Dm0600 "$PROJECT_DIR/config.example" "$target/etc/rayfw/rules.conf"
    install -Dm0644 "$PROJECT_DIR/packaging/systemd/rayfw.service" \
        "$target/usr/lib/systemd/system/rayfw.service"
    install -Dm0644 "$PROJECT_DIR/packaging/bash-completion/rayfwctl" \
        "$target/usr/share/bash-completion/completions/rayfwctl"
    install -Dm0644 "$PROJECT_DIR/docs/rayfwctl.8" \
        "$target/usr/share/man/man8/rayfwctl.8"
}

write_post_install() {
    target=$1

    cat > "$target" <<EOF
#!/bin/sh
depmod -a '$KERNEL_RELEASE' >/dev/null 2>&1 || :
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    systemctl enable rayfw.service >/dev/null 2>&1 || :
fi
exit 0
EOF
    chmod 0755 "$target"
}

package_deb() {
    package_root=$WORK_DIR/deb
    package_arch=$(dpkg --print-architecture)
    package_file="rayfw-${PLATFORM}_${VERSION}_${package_arch}.deb"

    stage_payload "$package_root"
    mkdir -p "$package_root/DEBIAN"
    cat > "$package_root/DEBIAN/control" <<EOF
Package: rayfw
Version: $VERSION
Section: net
Priority: optional
Architecture: $package_arch
Depends: kmod
Maintainer: RayFireWall package
Description: RayFireWall kernel firewall for $KERNEL_RELEASE
 Native package containing the RayFireWall CLI and a module built for
 kernel $KERNEL_RELEASE.
EOF
    printf '%s\n' '/etc/rayfw/rules.conf' > "$package_root/DEBIAN/conffiles"
    write_post_install "$package_root/DEBIAN/postinst"
    dpkg-deb --root-owner-group --build "$package_root" "$OUTPUT_DIR/$package_file"
}

package_rpm() {
    rpm_topdir=$WORK_DIR/rpmbuild
    package_arch=$(uname -m)
    spec_file=$rpm_topdir/SPECS/rayfw.spec
    rpm_file=

    mkdir -p "$rpm_topdir/BUILD" "$rpm_topdir/BUILDROOT" "$rpm_topdir/RPMS" \
        "$rpm_topdir/SOURCES" "$rpm_topdir/SPECS"
    cat > "$spec_file" <<EOF
%global debug_package %{nil}
Name:           rayfw
Version:        $VERSION
Release:        1
Summary:        RayFireWall kernel firewall
License:        GPL-2.0-only
BuildArch:      $package_arch
Requires:       kmod

%description
RayFireWall CLI and a kernel module built for kernel $KERNEL_RELEASE.

%install
rm -rf %{buildroot}
install -Dm0755 $PROJECT_DIR/cli/rayfwctl %{buildroot}/usr/sbin/rayfwctl
install -Dm0644 $PROJECT_DIR/kernel/rayfw.ko %{buildroot}/lib/modules/$KERNEL_RELEASE/extra/rayfw.ko
install -Dm0600 $PROJECT_DIR/config.example %{buildroot}/etc/rayfw/rules.conf
install -Dm0644 $PROJECT_DIR/packaging/systemd/rayfw.service %{buildroot}/usr/lib/systemd/system/rayfw.service
install -Dm0644 $PROJECT_DIR/packaging/bash-completion/rayfwctl %{buildroot}/usr/share/bash-completion/completions/rayfwctl
install -Dm0644 $PROJECT_DIR/docs/rayfwctl.8 %{buildroot}/usr/share/man/man8/rayfwctl.8

%post
/sbin/depmod -a $KERNEL_RELEASE >/dev/null 2>&1 || :
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    systemctl enable rayfw.service >/dev/null 2>&1 || :
fi

%files
%config(noreplace) %attr(0600,root,root) /etc/rayfw/rules.conf
/usr/sbin/rayfwctl
/lib/modules/$KERNEL_RELEASE/extra/rayfw.ko
/usr/lib/systemd/system/rayfw.service
/usr/share/bash-completion/completions/rayfwctl
/usr/share/man/man8/rayfwctl.8*
EOF
    rpmbuild --define "_topdir $rpm_topdir" -bb "$spec_file"
    rpm_file=$(find "$rpm_topdir/RPMS" -type f -name '*.rpm' -print -quit)
    if [ -z "$rpm_file" ]; then
        echo "RPM 构建未生成产物。" >&2
        exit 1
    fi
    mv "$rpm_file" "$OUTPUT_DIR/rayfw-${PLATFORM}-${VERSION}-${package_arch}.rpm"
}

package_arch() {
    package_dir=$WORK_DIR/arch
    package_arch=$(uname -m)
    package_file=

    mkdir -p "$package_dir/payload"
    stage_payload "$package_dir/payload"
    cat > "$package_dir/rayfw.install" <<EOF
post_install() {
    depmod -a '$KERNEL_RELEASE' >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable rayfw.service >/dev/null 2>&1 || true
}

post_upgrade() {
    post_install
}
EOF
    cat > "$package_dir/PKGBUILD" <<EOF
pkgname=rayfw
pkgver=$VERSION
pkgrel=1
pkgdesc='RayFireWall kernel firewall'
arch=('$package_arch')
license=('GPL-2.0-only')
depends=('kmod')
backup=('etc/rayfw/rules.conf')
install=rayfw.install

package() {
    cp -a "\$startdir/payload/." "\$pkgdir/"
    chown -R 0:0 "\$pkgdir"
}
EOF
    if ! id -u rayfwbuild >/dev/null 2>&1; then
        useradd -m -s /bin/sh rayfwbuild
    fi
    chown -R rayfwbuild:rayfwbuild "$package_dir"
    runuser -u rayfwbuild -- sh -c "cd '$package_dir' && makepkg --cleanbuild --noconfirm"
    package_file=$(find "$package_dir" -maxdepth 1 -type f -name '*.pkg.tar.*' \
        ! -name '*-debug-*' -print -quit)
    if [ -z "$package_file" ]; then
        echo "Arch 包构建未生成产物。" >&2
        exit 1
    fi
    package_file_name=${package_file##*/rayfw-}
    mv "$package_file" "$OUTPUT_DIR/rayfw-${PLATFORM}-$package_file_name"
}

mkdir -p "$OUTPUT_DIR"
case "$FORMAT" in
    deb) package_deb ;;
    rpm) package_rpm ;;
    arch) package_arch ;;
    *)
        echo "不支持的原生包格式: $FORMAT" >&2
        exit 64
        ;;
esac

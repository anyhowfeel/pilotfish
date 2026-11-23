FROM archlinux:latest

RUN pacman -Syu --noconfirm --needed base-devel git rust pkgconf libxkbcommon wayland libx11 libxcursor libxrandr libxi mesa \
    && pacman -Scc --noconfirm \
    && mkdir -m 1777 /cache
ENV CARGO_HOME=/cache/cargo HOME=/cache
WORKDIR /src

cmake_minimum_required(VERSION 2.8.10)
project(frivpn)

add_subdirectory(libfrivpn)

install(FILES frivpn_client.lua
    DESTINATION bin
    RENAME frivpn_client
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                GROUP_EXECUTE GROUP_READ
                WORLD_EXECUTE WORLD_READ
)

install(FILES seccomp_filter.lua syscalls_armel_eabi.lua syscalls_x86_64.lua utils.lua
    DESTINATION lib/frivpn
)

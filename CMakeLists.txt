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

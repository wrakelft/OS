add_executable(
    vtsh
    vtsh.c
)

set_target_properties(vtsh PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_custom_command(TARGET vtsh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:vtsh> ${CMAKE_SOURCE_DIR}/bin/vtsh
        COMMAND chmod +x ${CMAKE_SOURCE_DIR}/bin/vtsh
)

add_custom_command(TARGET vtsh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:vtsh> ${CMAKE_SOURCE_DIR}/test/vtsh
        COMMAND chmod +x ${CMAKE_SOURCE_DIR}/test/vtsh
)

target_include_directories(
    vtsh
    PUBLIC
    .
)

target_link_libraries(
    vtsh
    PRIVATE
    libvtsh
)

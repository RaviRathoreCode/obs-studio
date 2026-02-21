project(obs-license)

add_library(obs-license MODULE
    license.cpp
)

target_link_libraries(obs-license
    libobs
    Crypt32
)

target_compile_features(obs-license PRIVATE cxx_std_17)

set_target_properties(obs-license PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    FOLDER "plugins"
)

# Copy to rundir (always works, no admin needed)
add_custom_command(TARGET obs-license POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_BINARY_DIR}/rundir/$<CONFIG>/obs-plugins/64bit/"
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:obs-license>"
        "${CMAKE_BINARY_DIR}/rundir/$<CONFIG>/obs-plugins/64bit/"
    COMMENT "Copying plugin to rundir"
)

# Create locale files in rundir
add_custom_command(TARGET obs-license POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_BINARY_DIR}/rundir/$<CONFIG>/data/obs-plugins/obs-license/locale"
    COMMAND ${CMAKE_COMMAND} -E echo "[obs-license]" >
        "${CMAKE_BINARY_DIR}/rundir/$<CONFIG>/data/obs-plugins/obs-license/locale/en-US.ini"
    COMMAND ${CMAKE_COMMAND} -E echo "LicenseStatus=License Status" >>
        "${CMAKE_BINARY_DIR}/rundir/$<CONFIG>/data/obs-plugins/obs-license/locale/en-US.ini"
    COMMAND ${CMAKE_COMMAND} -E echo "Valid=Valid" >>
        "${CMAKE_BINARY_DIR}/rundir/$<CONFIG>/data/obs-plugins/obs-license/locale/en-US.ini"
    COMMAND ${CMAKE_COMMAND} -E echo "Invalid=Invalid" >>
        "${CMAKE_BINARY_DIR}/rundir/$<CONFIG>/data/obs-plugins/obs-license/locale/en-US.ini"
    COMMENT "Creating locale files"
)
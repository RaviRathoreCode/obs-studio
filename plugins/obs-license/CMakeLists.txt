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

# Correct install command
install(TARGETS obs-license
    RUNTIME DESTINATION obs-plugins/64bit
    LIBRARY DESTINATION obs-plugins/64bit
)
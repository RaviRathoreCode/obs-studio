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
    FOLDER "plugins"
)

install(TARGETS obs-license
    LIBRARY DESTINATION obs-plugins/64bit
    RUNTIME DESTINATION obs-plugins/64bit
)

# 🔹 Install locale files
install(DIRECTORY data/
    DESTINATION data/obs-plugins/obs-license
)
project(cJSON)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    cJSON

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://codeload.github.com/DaveGamble/cJSON/zip/master"
    URL_HASH SHA256=1d373c9df656b96e1479e1a0e0de02d67766ac02d88c353925a4782763b97f8f
    DOWNLOAD_NAME "cJSON-master.zip"
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        -DENABLE_CJSON_UTILS=On
        -DENABLE_CJSON_TEST=Off
        -DBUILD_SHARED_LIBS=Off
        ${CMAKE_ARGS_INIT}
)


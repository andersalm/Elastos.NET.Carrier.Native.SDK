project(Elastos.NET.Hive.Native.SDK)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    Elastos.NET.Hive.Native.SDK

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    GIT_REPOSITORY "https://github.com/elastos/Elastos.NET.Hive.Native.SDK.git"
    GIT_TAG "6d12f1e7424ce9a5dba0bae3f73605d1c921673d"
    GIT_SHALLOW 1
    GIT_PROGRESS 1


    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        -DJSON_FOR_MODERN_CXX_INCLUDE_DIR:PATH=../Elastos.NET.Hive.Native.SDK/json/include
)



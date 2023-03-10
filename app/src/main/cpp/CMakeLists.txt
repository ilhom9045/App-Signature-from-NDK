
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.22.1)

# Declares and names the project.

project("native-lib")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions("-DMY_DEBUG")
else(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions("-DMY_RELEASE")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

add_library( # Sets the name of the library.
        native-lib

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        native-lib.c
        unzip_helper.c
        path_helper.c
        pkcs7_helper.c
        md5.c

        third/minizip/mz_os.c
        third/minizip/mz_os_posix.c
        third/minizip/mz_strm_zlib.c
        third/minizip/mz_strm.c
        third/minizip/mz_strm_buf.c
        third/minizip/mz_strm_mem.c
        third/minizip/mz_strm_posix.c
        third/minizip/mz_strm_split.c
        third/minizip/mz_zip.c)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)
find_library( # Sets the name of the path variable.
        z-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        z)
# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
        native-lib

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib}
        ${z-lib})

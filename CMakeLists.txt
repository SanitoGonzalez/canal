cmake_minimum_required(VERSION 3.28)
project(canal LANGUAGES C)

### Setup
if(NOT IS_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bootstrap)
    execute_process(
        COMMAND make bootstrap OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
    )

else()
    message(STATUS "Skipping bootstrapping")
endif()
set(bootstrap_dir ${CMAKE_CURRENT_BINARY_DIR}/bootstrap)
set(bpftool_EXECUTABLE ${bootstrap_dir}/bpftool)
set(libbpf_INCLUDE_DIRS ${bootstrap_dir}/libbpf/include)
set(libbpf_LIBRARIES ${bootstrap_dir}/libbpf/libbpf.a)


set(vmlinux_dir ${CMAKE_CURRENT_BINARY_DIR}/vmlinux)
set(vmlinux ${vmlinux_dir}/vmlinux.h)
if (NOT IS_DIRECTORY ${vmlinux_dir})
    file(MAKE_DIRECTORY ${vmlinux_dir})
    execute_process(
        COMMAND ${bpftool_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c
        OUTPUT_FILE ${vmlinux}
        ERROR_VARIABLE vmlinux_error
        RESULT_VARIABLE vmlinux_result
    )
    if (NOT ${vmlinux_result} EQUAL 0)
        message(FATAL_ERROR "Failed to dump vmlinux.h from BTF: ${vmlinux_error}")
    endif()
else()
    message(STATUS "Skipping vmlinux.h dumping")
endif()


### Build bpf objects
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bpfobjects)
function(bpfobject bpf_c)
    get_filename_component(name ${bpf_c} NAME_WE)
    get_filename_component(dir ${bpf_c} DIRECTORY)

    set(bpf_dir ${CMAKE_CURRENT_BINARY_DIR}/bpfobjects)
    set(bpf_o ${bpf_dir}/${name}.bpf.o)
    set(bpf_skel ${bpf_dir}/${name}.skel.h)
    set(bpf_target ${name}_skel)

    add_custom_command( 
        OUTPUT ${bpf_o}
        COMMAND 
            clang -g -O2 -Wall -target bpf 
            -I${vmlinux_dir} -I${libbpf_INCLUDE_DIRS}
             -c ${bpf_c} -o ${bpf_o}
        VERBATIM
        DEPENDS ${bpf_c}
        COMMENT "[clang] Building BPF object: ${bpf_o}"
    )

    add_custom_command(
        OUTPUT ${bpf_skel}
        COMMAND bash -c "${bpftool_EXECUTABLE} gen skeleton ${bpf_o} > ${bpf_skel}"
        VERBATIM
        DEPENDS ${bpf_o}
        COMMENT "[skel] Building BPF skeleton: ${name}"
    )

    add_library(${bpf_target} INTERFACE)
    target_sources(${bpf_target} INTERFACE ${bpf_skel})
    target_include_directories(${bpf_target} INTERFACE ${bpf_dir} ${libbpf_INCLUDE_DIRS})
    target_link_libraries(${bpf_target} INTERFACE ${libbpf_LIBRARIES} -lelf -lz)
endfunction()


file(GLOB apps
    canal/*.bpf.c
)

foreach(app ${apps})
    get_filename_component(app_name ${app} NAME_WE)
    get_filename_component(app_dir ${app} DIRECTORY)

    bpfobject(${app})
    if (NOT TARGET ${app_name}_skel)
        message(FATAL_ERROR "target ${app_name}_skel not exist")
    endif()

    add_executable(${app_name} ${app_dir}/${app_name}.c)
    target_link_libraries(${app_name} PRIVATE ${app_name}_skel)
endforeach()
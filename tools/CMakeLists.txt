add_executable(trunc-o-matic trunc-o-matic.c)
target_link_libraries(trunc-o-matic netdissect ${TCPDUMP_LINK_LIBRARIES})

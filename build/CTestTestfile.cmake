# CMake generated Testfile for 
# Source directory: E:/ProtocolStack
# Build directory: E:/ProtocolStack/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(eth_in "E:/ProtocolStack/build/eth_in.exe" "E:/ProtocolStack/testing/data/eth_in")
set_tests_properties(eth_in PROPERTIES  _BACKTRACE_TRIPLES "E:/ProtocolStack/CMakeLists.txt;117;add_test;E:/ProtocolStack/CMakeLists.txt;0;")
add_test(eth_out "E:/ProtocolStack/build/eth_out.exe" "E:/ProtocolStack/testing/data/eth_out")
set_tests_properties(eth_out PROPERTIES  _BACKTRACE_TRIPLES "E:/ProtocolStack/CMakeLists.txt;122;add_test;E:/ProtocolStack/CMakeLists.txt;0;")
add_test(arp_test "E:/ProtocolStack/build/arp_test.exe" "E:/ProtocolStack/testing/data/arp_test")
set_tests_properties(arp_test PROPERTIES  _BACKTRACE_TRIPLES "E:/ProtocolStack/CMakeLists.txt;127;add_test;E:/ProtocolStack/CMakeLists.txt;0;")
add_test(ip_test "E:/ProtocolStack/build/ip_test.exe" "E:/ProtocolStack/testing/data/ip_test")
set_tests_properties(ip_test PROPERTIES  _BACKTRACE_TRIPLES "E:/ProtocolStack/CMakeLists.txt;132;add_test;E:/ProtocolStack/CMakeLists.txt;0;")
add_test(ip_frag_test "E:/ProtocolStack/build/ip_frag_test.exe" "E:/ProtocolStack/testing/data/ip_frag_test")
set_tests_properties(ip_frag_test PROPERTIES  _BACKTRACE_TRIPLES "E:/ProtocolStack/CMakeLists.txt;137;add_test;E:/ProtocolStack/CMakeLists.txt;0;")
add_test(icmp_test "E:/ProtocolStack/build/icmp_test.exe" "E:/ProtocolStack/testing/data/icmp_test")
set_tests_properties(icmp_test PROPERTIES  _BACKTRACE_TRIPLES "E:/ProtocolStack/CMakeLists.txt;142;add_test;E:/ProtocolStack/CMakeLists.txt;0;")

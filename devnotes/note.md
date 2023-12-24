
I found that kernel reuses network namespaces of dead processes.

Therefore running `sproxy veth` consecutively results in one node with multiple veths, with some of them non existent.
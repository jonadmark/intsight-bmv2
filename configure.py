import json
import sys

import networkx as nx

# 3072 8 4

LBW = 100  # Mbps
Q_RATE = 8928  # packets/second (default: 3072) 8400 6300
Q_DEPTH_FRAC = 8
CTH_DEPTH_FRAC = 8  # 4 bw, 8 burst
Q_DEPTH = int(Q_RATE/Q_DEPTH_FRAC)  # packets (default: 128) Q_RATE/20
# packets (1/4 of queue capacity, default: 32) Q_DEPTH/4
CTH_DEPTH = int(Q_DEPTH/CTH_DEPTH_FRAC)
# microseconds 10000 (default: 10000) SLA DEPENDENT
CTH_TIMEDELTA = int((1000000/Q_DEPTH_FRAC)/CTH_DEPTH_FRAC)


def main(net_file):

    with open(net_file, 'r') as f:
        net = json.load(f)
    
    n_nodes = net['nodes']
    hosts_per_switch = net['hosts_per_node']
    node_links = net['node_links']
    e2e_delay_slas = net['e2e_delay_slas'] if 'e2e_delay_slas' in net else {}
    bandwidth_slas = net['bandwidth_slas'] if 'bandwidth_slas' in net else {}
    all_links = []

    nodes = {}
    hosts = {}

    table_entries = {}

    # create telemetry sink node
    node_num = 0
    nid = 's0'
    nodes[nid] = {
        'id': nid,
        'num': node_num,
        'ip': '10.0.0.0',
        'mac': '01:02:04:08:16:32',
        'adj': []
    }
    table_entries[nid] = []

    # create nodes and hosts
    for i in range(n_nodes):
        node_num = i + 1
        nid = 's{}'.format(node_num)
        table_entries[nid] = []
        nodes[nid] = {
            'id': nid,
            'num': node_num,
            'ip': '10.0.{}.0'.format(node_num),
            'mac': '00:00:00:00:{:02X}:00'.format(node_num),
            'adj': []
        }
        for j in range(hosts_per_switch):
            host_num = i*hosts_per_switch + j + 1
            hid = 'h{}'.format(host_num)
            hosts[hid] = {
                'id': hid,
                'num': host_num,
                'ip': '10.0.{}.{}'.format(node_num, host_num),
                'mac': '00:00:00:00:{:02X}:{:02X}'.format(node_num, host_num),
                'adj': nid
            }
            # add adjacency to hosts
            nodes[nid]['adj'].append(hid)
            all_links.append([hid, nid, '0us', LBW])
            # mac address
            table_entries[nid].append({
                "table": "egress.mac_addrs",
                "match": {
                    "smd.egress_port": j + 1
                },
                "action_name": "egress.rewrite_mac_addrs",
                "action_params": {
                    "src": nodes[nid]['mac'],
                    "dst": hosts[hid]['mac']
                }
            })

        # add adjacency to telemetry sink node
        nodes['s0']['adj'].append(nid)
        nodes[nid]['adj'].append('s0')
        # all_links.append(['s0', nid, '0us'])
        all_links.append(['s0', nid, '0us', LBW])
        table_entries[nid].append({
            "table": "egress.mac_addrs",
            "match": {
                "smd.egress_port": hosts_per_switch + 1
            },
            "action_name": "egress.rewrite_mac_addrs",
            "action_params": {
                "src": nodes[nid]['mac'],
                "dst": nodes['s0']['mac']
            }
        })
        # node and analyzer IP addresses
        table_entries[nid].append({
            "table": "egress.node_and_analyzer_IP_addr",
            "default_action": True,
            "action_name": "egress.set_node_and_analyzer_IP_addr",
            "action_params": {
                "node": nodes[nid]['ip'],
                "analyzer": "10.0.0.0"
            }
        })
        # contention thresholds
        table_entries[nid].append({
            "table": "egress.contention_thresholds",
            "default_action": True,
            "action_name": "egress.set_contention_thresholds",
            "action_params": {
                "timedelta": CTH_TIMEDELTA,
                "depth": CTH_DEPTH
            }
        })

    for link in node_links:
        if link[0] > link[1]:
            link[0], link[1] = link[1], link[0]
    
    link_sort_key = lambda x: (int(x[0][1:]), int(x[1][1:]))
    node_links.sort(key=link_sort_key)

    # add node to node adjacency
    # and build a graph from link list
    topo = nx.Graph()
    for link in node_links:
        uid, vid = link[0], link[1]
        # all_links.append([uid, vid, '0us'])
        all_links.append([uid, vid, '0us', LBW])
        topo.add_edge(uid, vid)
        nodes[uid]['adj'].append(vid)
        nodes[vid]['adj'].append(uid)
        # mac addresses
        table_entries[uid].append({
            "table": "egress.mac_addrs",
            "match": {
                "smd.egress_port": nodes[uid]['adj'].index(vid) + 1
            },
            "action_name": "egress.rewrite_mac_addrs",
            "action_params": {
                "src": nodes[uid]['mac'],
                "dst": nodes[vid]['mac']
            }
        })

        table_entries[vid].append({
            "table": "egress.mac_addrs",
            "match": {
                "smd.egress_port": nodes[vid]['adj'].index(uid) + 1
            },
            "action_name": "egress.rewrite_mac_addrs",
            "action_params": {
                "src": nodes[vid]['mac'],
                "dst": nodes[uid]['mac']
            }
        })
    
    shortest_paths = dict(nx.all_pairs_shortest_path(topo))
    
    # routing
    routing_entries = {}
    for u in nodes.keys():
        routing_entries[u] = {}

    table_entries['s0'].append({
        "table": "ingress.ipv4_lpm",
        "match": {
            "hdrs.ipv4.dst_addr": [nodes['s0']['ip'], 24]
        },
        "action_name": "ingress.drop",
        "action_params": {}
    })

    for src, paths in shortest_paths.items():
        for h in range(hosts_per_switch):
            table_entries[src].append({
                "table": "ingress.ipv4_lpm",
                "match": {
                    "hdrs.ipv4.dst_addr": [hosts[nodes[src]['adj'][h]]['ip'], 32]
                },
                "action_name": "ingress.ipv4_forward",
                "action_params": {
                    "port": h + 1
                }
            })

        for dst, path in paths.items():
            if src == dst:
                routing_entries[src][dst] = -1
                # drop packets directed to itself
                table_entries[src].append({
                    "table": "ingress.ipv4_lpm",
                    "match": {
                        "hdrs.ipv4.dst_addr": [nodes[src]['ip'], 24]
                    },
                    "action_name": "ingress.drop",
                    "action_params": {}
                })
                # forwarding packets directed to sink via port 'hosts_per_node + 1'
                table_entries[src].append({
                    "table": "ingress.ipv4_lpm",
                    "match": {
                        "hdrs.ipv4.dst_addr": [nodes['s0']['ip'], 24]
                    },
                    "action_name": "ingress.ipv4_forward",
                    "action_params": {
                        "port": hosts_per_switch + 1
                    }
                })
            else:
                for i in range(len(path) - 1):
                    u = path[i]
                    v = path[i + 1]
                    if dst not in routing_entries[u]:
                        routing_entries[u][dst] = nodes[u]['adj'].index(v) + 1
                        table_entries[u].append({
                            "table": "ingress.ipv4_lpm",
                            "match": {
                                "hdrs.ipv4.dst_addr": [nodes[dst]['ip'], 24]
                            },
                            "action_name": "ingress.ipv4_forward",
                            "action_params": {
                                "port": nodes[u]['adj'].index(v) + 1
                            }
                        })
                    else:
                        if routing_entries[u][dst] != nodes[u]['adj'].index(v) + 1:
                            print('error!')

    # flow IDs
    last_flow_ID = {}
    for nid in nodes:
        last_flow_ID[nid] = 0

    for uid, hu in sorted(hosts.items(), key=lambda x: int(x[0][1:])):
        for vid, hv in sorted(hosts.items(), key=lambda x: int(x[0][1:])):
            if uid < vid:
                uadj = hu['adj']
                vadj = hv['adj']

                ######################
                # FLOW: uid ===>>> vid
                ######################
                # Ingress node
                flow_ID_uadj = last_flow_ID[uadj] + 1
                last_flow_ID[uadj] = last_flow_ID[uadj] + 1
                table_entries[uadj].append({
                    "table": "ingress.flow_ID",
                    "match": {
                        "hdrs.ipv4.src_addr": hu['ip'],
                        "hdrs.ipv4.dst_addr": hv['ip']
                    },
                    "action_name": "ingress.set_flow_ID",
                    "action_params": {
                        "flow_ID": flow_ID_uadj
                    }
                })
                # # test code - beginning
                # table_entries[uadj].append({
                #     "table": "ingress.flow_ID",
                #     "match": {
                #         "hdrs.ipv4.src_addr": hu['ip'],
                #         "hdrs.ipv4.dst_addr": hv['ip']
                #     },
                #     "action_name": "ingress.set_flow_ID",
                #     "action_params": {
                #         "flow_ID": flow_ID_uadj
                #     }
                # })
                # # test code - end

                # Egress node
                if uadj == vadj:
                    # the flow ID is the same because we are in the same node
                    flow_ID_vadj = flow_ID_uadj
                else:  # uadj != vadj
                    # we need a new flow ID
                    flow_ID_vadj = last_flow_ID[vadj] + 1
                    last_flow_ID[vadj] = last_flow_ID[vadj] + 1
                    # and a rule at the node adj to u
                    table_entries[vadj].append({
                        "table": "ingress.flow_ID",
                        "match": {
                            "hdrs.ipv4.src_addr": hu['ip'],
                            "hdrs.ipv4.dst_addr": hv['ip']
                        },
                        "action_name": "ingress.set_flow_ID",
                        "action_params": {
                            "flow_ID": flow_ID_vadj
                        }
                    })
                    # # test code - beginning
                    # table_entries[vadj].append({
                    #     "table": "ingress.flow_ID",
                    #     "match": {
                    #         "hdrs.ipv4.src_addr": hu['ip'],
                    #         "hdrs.ipv4.dst_addr": hv['ip']
                    #     },
                    #     "action_name": "ingress.set_flow_ID",
                    #     "action_params": {
                    #         "flow_ID": flow_ID_vadj
                    #     }
                    # })
                    # # test code - end
                # if there is an e2e delay SLA from u to v
                if uid in e2e_delay_slas and vid in e2e_delay_slas[uid]:
                    # e2e delay threshold
                    table_entries[vadj].append({
                        "table": "egress.e2e_delay_threshold",
                        "match": {
                            "cmd.flow_ID": flow_ID_vadj
                        },
                        "action_name": "egress.set_e2e_delay_threshold",
                        "action_params": {
                            "threshold": e2e_delay_slas[uid][vid][0]
                        }
                    })
                    # number of high delays threshold
                    table_entries[vadj].append({
                        "table": "egress.high_delays_threshold",
                        "match": {
                            "cmd.flow_ID": flow_ID_vadj
                        },
                        "action_name": "egress.set_high_delays_threshold",
                        "action_params": {
                            "threshold": e2e_delay_slas[uid][vid][1]
                        }
                    })
                if uid in bandwidth_slas and vid in bandwidth_slas[uid]:
                    # bandwidth thresholds
                    table_entries[vadj].append({
                        "table": "egress.bandwidth_thresholds",
                        "match": {
                            "cmd.flow_ID": flow_ID_vadj
                        },
                        "action_name": "egress.set_bandwidth_thresholds",
                        "action_params": {
                            "bandwidth": bandwidth_slas[uid][vid][0],
                            "drops": bandwidth_slas[uid][vid][1]
                        }
                    })

                ######################
                # FLOW: uid <<<=== vid
                ######################
                # Ingress node
                flow_ID_vadj = last_flow_ID[vadj] + 1
                last_flow_ID[vadj] = last_flow_ID[vadj] + 1
                table_entries[vadj].append({
                    "table": "ingress.flow_ID",
                    "match": {
                        "hdrs.ipv4.src_addr": hv['ip'],
                        "hdrs.ipv4.dst_addr": hu['ip']
                    },
                    "action_name": "ingress.set_flow_ID",
                    "action_params": {
                        "flow_ID": flow_ID_vadj
                    }
                })
                # # test code - beginning
                # table_entries[vadj].append({
                #     "table": "ingress.flow_ID",
                #     "match": {
                #         "hdrs.ipv4.src_addr": hv['ip'],
                #         "hdrs.ipv4.dst_addr": hu['ip']
                #     },
                #     "action_name": "ingress.set_flow_ID",
                #     "action_params": {
                #         "flow_ID": flow_ID_vadj
                #     }
                # })
                # # test code - end

                # Egress node
                if vadj == uadj:
                    # the flow ID is the same because we are in the same node
                    flow_ID_uadj = flow_ID_vadj
                else:
                    # we need a new flow ID
                    flow_ID_uadj = last_flow_ID[uadj] + 1
                    last_flow_ID[uadj] = last_flow_ID[uadj] + 1
                    # and a rule at the node adj to u
                    table_entries[uadj].append({
                        "table": "ingress.flow_ID",
                        "match": {
                            "hdrs.ipv4.src_addr": hv['ip'],
                            "hdrs.ipv4.dst_addr": hu['ip']
                        },
                        "action_name": "ingress.set_flow_ID",
                        "action_params": {
                            "flow_ID": flow_ID_uadj
                        }
                    })
                    # # test code - beginning
                    # table_entries[uadj].append({
                    #     "table": "ingress.flow_ID",
                    #     "match": {
                    #         "hdrs.ipv4.src_addr": hv['ip'],
                    #         "hdrs.ipv4.dst_addr": hu['ip']
                    #     },
                    #     "action_name": "ingress.set_flow_ID",
                    #     "action_params": {
                    #         "flow_ID": flow_ID_uadj
                    #     }
                    # })
                    # # test code - end
                # if there is an e2e delay SLA from u to v
                if vid in e2e_delay_slas and uid in e2e_delay_slas[vid]:
                    # e2e delay threshold
                    table_entries[uadj].append({
                        "table": "egress.e2e_delay_threshold",
                        "match": {
                            "cmd.flow_ID": flow_ID_uadj
                        },
                        "action_name": "egress.set_e2e_delay_threshold",
                        "action_params": {
                            "threshold": e2e_delay_slas[vid][uid][0]
                        }
                    })
                    # number of high delays threshold
                    table_entries[uadj].append({
                        "table": "egress.high_delays_threshold",
                        "match": {
                            "cmd.flow_ID": flow_ID_uadj
                        },
                        "action_name": "egress.set_high_delays_threshold",
                        "action_params": {
                            "threshold": e2e_delay_slas[vid][uid][1]
                        }
                    })
                if vid in bandwidth_slas and uid in bandwidth_slas[vid]:
                    # bandwidth thresholds
                    table_entries[uadj].append({
                        "table": "egress.bandwidth_thresholds",
                        "match": {
                            "cmd.flow_ID": flow_ID_uadj
                        },
                        "action_name": "egress.set_bandwidth_thresholds",
                        "action_params": {
                            "bandwidth": bandwidth_slas[vid][uid][0],
                            "drops": bandwidth_slas[vid][uid][1]
                        }
                    })

            # if uid != vid:
            #     # to
            #     flow_ID_to = last_flow_ID[hu['adj']] + 1
            #     last_flow_ID[hu['adj']] = last_flow_ID[hu['adj']] + 1
                
            #     table_entries[hu['adj']].append({
            #         "table": "egress.flow_ID",
            #         "match": {
            #             "hdrs.ipv4.src_addr": hu['ip'],
            #             "hdrs.ipv4.dst_addr": hv['ip']
            #         },
            #         "action_name": "egress.set_flow_ID",
            #         "action_params": {
            #             "flow_ID": flow_ID_to
            #         }
            #     })
                
            #     # fro
            #     if hu['adj'] != hv['adj']:
            #         table_entries[hu['adj']].append({
            #             "table": "egress.flow_ID",
            #             "match": {
            #                 "hdrs.ipv4.src_addr": hv['ip'],
            #                 "hdrs.ipv4.dst_addr": hu['ip']
            #             },
            #             "action_name": "egress.set_flow_ID",
            #             "action_params": {
            #                 "flow_ID": last_flow_ID[hu['adj']] + 1
            #             }
            #         })
            #         last_flow_ID[hu['adj']] = last_flow_ID[hu['adj']] + 1
    
    # GENERATE FILES
    all_links.sort(key=lambda x: (x[0][0], int(x[0][1:]), int(x[1][1:])))
    # generate topology configuration file
    topology_cfg = {
        "capture_traffic": net['capture_traffic'],
        "run_workload": net['run_workload'],
        "workload_file": net['workload_file'],
        "hosts": list(hosts.keys()),
        "switches": {},
        "links": all_links
    }
    for nid, node in nodes.items():
        if nid == 's0':
            topology_cfg['switches'][nid] = {
                "runtime_json": "s0-runtime.json"
            }
        else:
            topology_cfg['switches'][nid] = {
                "runtime_json": "{}-runtime.json".format(nid),
                "cli_input": "{}-cli.txt".format(nid)
            }
    
    print('building topology.json', end='... ')
    with open('topology.json', 'w') as f:
        json.dump(topology_cfg, f, indent=4)
    print('done')

    # generate device configuration files
    for nid, node in nodes.items():
        # Runtime configuration
        node_runtime_cfg = {
            "target": "bmv2",
            "p4info": "build/intsight.p4info",
            "bmv2_json": "build/intsight.json",
            "table_entries": table_entries[nid]
        }
        print('building {}-runtime.json'.format(nid), end='... ')
        with open('{}-runtime.json'.format(nid), 'w') as f:
            json.dump(node_runtime_cfg, f, indent=4)
        print('done')

        # Runtime configuration via CLI
        node_cli_cfg = "register_write ingress.node_ID 0 {}\n".format(
            node['num']
        )
        node_cli_cfg += "mirroring_add 42 {}\n".format(hosts_per_switch + 1)
        node_cli_cfg += "set_queue_depth {}\n".format(Q_DEPTH)
        node_cli_cfg += "set_queue_rate {}\n".format(Q_RATE)
        print('building {}-cli.txt'.format(nid), end='... ')
        with open('{}-cli.txt'.format(nid), 'w') as f:
            f.write(node_cli_cfg)
        print('done')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print('Usage: python3 configure.py <network_json>')
    # main('network2.json')

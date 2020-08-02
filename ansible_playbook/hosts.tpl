# Consul cluster node hosts configuration
#
# NB: Replace the hosts below with your preferred node hostnames and continue
#     the 'nodeN' pattern for additional nodes past 'consul3'. There should
#     be only one node with consul_node_role = "bootstrap"
#     Do not modify the labels (text appearing between []), however


[vault_instances]
%{ for n in range(nvault_instance) ~}
${fqdns[n]} vault_raft_node_id='vault-node${n}' vault_tls_cert_file='fullchain1.pem' vault_tls_key_file='privkey1.pem'
%{ endfor ~}


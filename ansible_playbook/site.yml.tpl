---
# File: site.yml - Example Vault site playbook
# ansible-playbook -i hosts site.yml

- name: Install Vault
  hosts: vault_instances
  any_errors_fatal: true
  become: true
  become_user: root
  tags:
   - vault
  roles:
   - { role: ansible-vault } # It will install vault on the vms.
  vars:
   vault_iface: "{{ansible_default_ipv4.interface}}"
   vault_install_remotely: true
   vault_version: "${vault_version}"
   vault_api_addr: "https://{{inventory_hostname}}:8200"
   vault_pkg: "vault_{{vault_version}}+ent_linux_amd64.zip"
   vault_checksum_file_url: "https://releases.hashicorp.com/vault/{{vault_version}}+ent/vault_{{vault_version}}+ent_SHA256SUMS"
   vault_zip_url: "https://releases.hashicorp.com/vault/{{vault_version}}+ent/vault_{{vault_version}}+ent_linux_amd64.zip"
   vault_max_lease_ttl: "87600h"
   vault_plugin_path: "etc/vault/plugins"
   vault_ui: true
   vault_tls_disable: false
   vault_tls_src_files: ./files
   vault_tls_ca_file: "chain1.pem"
   validate_certs_during_api_reachable_check: false
   vault_telemetry_enabled: true
   vault_prometheus_retention_time: "30s"
   vault_telemetry_disable_hostname: true
   vault_backend: "raft"
   vault_data_path: "/var/vault"
   vault_dns_disable: false
